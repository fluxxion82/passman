package ai.passman.platform.transfer

import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.HybridKem
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.MlDsa
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import com.k2k.test.tls.K2kClientTls
import java.io.File
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * The per-[PairingSecurity] dispatch that used to be copy-pasted into three transfer services, now
 * owned by [ArtifactSyncClient] and driven through a recording [SyncNetwork] instead of a socket.
 *
 * Everything asserted here is wire contract rather than implementation taste: which key material a
 * pairing may use, which route and kind string each artifact takes, the exact `Outcome.Error`
 * strings, and — the two properties that are silent failures in production — that an upgraded
 * pairing never fetches key material over the wire and never accepts a pulled payload that was not
 * signed by the peer key stored at pairing.
 *
 * Real crypto throughout (`EnvelopeCodec`/`HybridKem`/`MlDsa`, real [HybridKeyManager] and
 * [MlDsaKeyManager] over a temp directory): a fake codec would let a policy regression pass by
 * agreeing with itself. Only the network is faked, because the live-loopback proof that the client
 * still speaks real k2k lives in `SignedHybridSyncPolicyTest`.
 */
@OptIn(ExperimentalEncodingApi::class)
class ArtifactSyncClientTest {
    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var sessionKey: VaultSessionKey
    private val preferences = FakePreferences()
    private val network = FakeSyncNetwork()

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("artifact-sync-client").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        startSession(withIdentity = true)
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        root.deleteRecursively()
    }

    // ------------------------------------------------------------------ legacy pairings: push

    @Test
    fun legacyPush_fetchesPeerKeysOverTheWire_andSignsWhenTheirMlDsaKeyIsWellFormed() = runBlocking<Unit> {
        network.serve("hybridPublicKey", EnvelopeCodec.serializePublicKey(peerHybrid.publicKey))
        network.serve("mldsaPublicKey", peerMlDsa.publicKey)
        val client = client(FakeTrustedDevices(legacyDevice()))

        val outcome = client.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertEquals(
            listOf("hybridPublicKey", "mldsaPublicKey"),
            network.downloadRequests,
            "a legacy pairing keeps fetching both peer keys over the mTLS channel",
        )
        val upload = network.uploads.single()
        assertEquals(FILE_NAME, upload.fileName)
        assertEquals(HOST, upload.host)
        assertEquals(PORT, upload.port)
        assertEquals(4, upload.bytes[5], "a well-formed peer ML-DSA key makes signing happen (suite 4)")
        assertContentEquals(
            PAYLOAD,
            EnvelopeCodec.decryptSignedHybrid(upload.bytes, peerHybrid.privateKey, localMlDsaPublicKey()),
            "the envelope must open with the wire-served peer key and verify against this device's signer",
        )
    }

    @Test
    fun legacyPush_withAMalformedPeerMlDsaKey_uploadsAnUnsignedEnvelope() = runBlocking<Unit> {
        network.serve("hybridPublicKey", EnvelopeCodec.serializePublicKey(peerHybrid.publicKey))
        // Not MlDsa.PUBLIC_KEY_BYTES long: signing is opportunistic on the legacy path, so a peer that
        // cannot verify must still receive a payload it can open.
        network.serve("mldsaPublicKey", ByteArray(7))
        val client = client(FakeTrustedDevices(legacyDevice()))

        assertIs<Outcome.Success<Unit>>(client.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT))

        val upload = network.uploads.single()
        assertEquals(3, upload.bytes[5], "a mis-sized peer key means no signature (suite 3)")
        assertContentEquals(PAYLOAD, EnvelopeCodec.decrypt(upload.bytes, peerHybrid.privateKey))
        assertFailsWith<IllegalArgumentException>("and the envelope genuinely carries no signature") {
            EnvelopeCodec.decryptSignedHybrid(upload.bytes, peerHybrid.privateKey, localMlDsaPublicKey())
        }
    }

    // ------------------------------------------------------------------ legacy pairings: pull

    @Test
    fun legacyPull_decryptsAgainstTheWireServedMlDsaKey() = runBlocking<Unit> {
        val payload = "legacy pulled vault".encodeToByteArray()
        network.serve("mldsaPublicKey", peerMlDsa.publicKey)
        network.pullResponse = { _, clientKey ->
            EnvelopeCodec.encryptHybrid(payload, EnvelopeCodec.deserializePublicKey(clientKey), peerMlDsa)
        }
        val client = client(FakeTrustedDevices(legacyDevice()))

        val outcome = client.pull(SyncArtifact.Passwords, HOST, PORT)

        assertContentEquals(payload, assertIs<Outcome.Success<ByteArray>>(outcome).value)
        assertEquals(listOf("mldsaPublicKey"), network.downloadRequests)
        val pull = network.pulls.single()
        assertEquals("passwords", pull.kind)
        assertContentEquals(
            EnvelopeCodec.serializePublicKey(localHybridKeyPair().publicKey),
            pull.clientKey,
            "the caller offers its own hybrid public key on the wire",
        )
    }

    // ------------------------------------------------------------------ upgraded pairings

    @Test
    fun strictPush_neverFetchesKeyMaterial_andSignsToTheStoredHybridKey() = runBlocking<Unit> {
        // A decoy on the wire: if the client fetched it, the envelope would not open with the stored key.
        network.serve("hybridPublicKey", EnvelopeCodec.serializePublicKey(HybridKem.generateKeyPair().publicKey))
        network.serve("mldsaPublicKey", MlDsa.generateKeyPair().publicKey)
        val client = client(FakeTrustedDevices(signedDevice()))

        val outcome = client.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertEquals(
            emptyList(),
            network.downloadRequests,
            "an upgraded pairing must never fetch key material over the wire",
        )
        val upload = network.uploads.single()
        assertEquals(4, upload.bytes[5], "an upgraded pairing always signs (suite 4)")
        assertContentEquals(
            PAYLOAD,
            EnvelopeCodec.decryptSignedHybrid(upload.bytes, peerHybrid.privateKey, localMlDsaPublicKey()),
            "the envelope must open with the STORED peer key, not the decoy served on the wire",
        )
    }

    @Test
    fun strictPull_acceptsOnlyAResponseSignedByTheStoredPeerKey() = runBlocking<Unit> {
        val payload = "pulled vault".encodeToByteArray()
        val devices = FakeTrustedDevices(signedDevice())

        // Fixture control: signed by the stored peer key, so the rejections below are about the signer
        // and not about a broken pull path.
        network.pullResponse = { _, clientKey ->
            EnvelopeCodec.encryptHybrid(payload, EnvelopeCodec.deserializePublicKey(clientKey), peerMlDsa)
        }
        assertContentEquals(
            payload,
            assertIs<Outcome.Success<ByteArray>>(client(devices).pull(SyncArtifact.Passwords, HOST, PORT)).value,
        )
        assertEquals(emptyList(), network.downloadRequests, "the verify key comes from the pairing record")

        // Well-formed, correctly signed — by an impostor's valid key rather than the stored one.
        network.pullResponse = { _, clientKey ->
            EnvelopeCodec.encryptHybrid(
                "forged".encodeToByteArray(),
                EnvelopeCodec.deserializePublicKey(clientKey),
                MlDsa.generateKeyPair(),
            )
        }
        assertIs<Outcome.Error>(
            client(devices).pull(SyncArtifact.Passwords, HOST, PORT),
            "a response signed by a different ML-DSA key must never come back as plaintext",
        )

        // The downgrade shape: a suite-3 envelope that would otherwise decrypt cleanly.
        network.pullResponse = { _, clientKey ->
            EnvelopeCodec.encryptHybrid("unsigned".encodeToByteArray(), EnvelopeCodec.deserializePublicKey(clientKey))
        }
        assertIs<Outcome.Error>(
            client(devices).pull(SyncArtifact.Passwords, HOST, PORT),
            "an unsigned response to an upgraded pairing is a downgrade, not a compatibility case",
        )
    }

    // ------------------------------------------------------------------ refusals, before any I/O

    @Test
    fun awaitingConfirmation_refusesPushAndPull_beforeAnyNetworkIo() = runBlocking<Unit> {
        val device = signedDevice().copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)
        val client = client(FakeTrustedDevices(device))

        val push = client.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)
        val pull = client.pull(SyncArtifact.Passwords, HOST, PORT)

        assertEquals(StoredPeerKeys.reverificationRefusal(device.name), assertIs<Outcome.Error>(push).message)
        assertEquals(StoredPeerKeys.reverificationRefusal(device.name), assertIs<Outcome.Error>(pull).message)
        assertEquals(TransferFailure.GeneralTransferFailure, assertIs<Outcome.Error>(push).cause)
        assertNoNetworkIo()
    }

    @Test
    fun unpairedHost_andUnavailableClientTls_refuseBeforeAnyNetworkIo() = runBlocking<Unit> {
        val unpaired = client(FakeTrustedDevices())

        assertEquals(
            UNRESOLVED,
            assertIs<Outcome.Error>(unpaired.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)).message,
        )
        assertEquals(
            UNRESOLVED,
            assertIs<Outcome.Error>(unpaired.pull(SyncArtifact.Passwords, HOST, PORT)).message,
        )
        assertNoNetworkIo()

        // A known device whose client TLS cannot be built (no session identity) is refused with the
        // same message — the pairing record alone is not permission to open a connection.
        stopKoin()
        startSession(withIdentity = false)
        val noTls = client(FakeTrustedDevices(legacyDevice()))

        assertEquals(
            "host not paired: $HOST",
            assertIs<Outcome.Error>(noTls.push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)).message,
        )
        assertEquals(
            "host not paired: $HOST",
            assertIs<Outcome.Error>(noTls.pull(SyncArtifact.Passwords, HOST, PORT)).message,
        )
        assertNoNetworkIo()
    }

    // ------------------------------------------------------------------ failure mapping

    @Test
    fun networkFailuresMapToTheirTransferFailures_andCancellationPropagates() = runBlocking<Unit> {
        val devices = FakeTrustedDevices(signedDevice())

        network.failWith = { ConnectException("connection refused") }
        val refused = assertIs<Outcome.Error>(client(devices).push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT))
        assertEquals("peer unreachable: connection refused", refused.message)
        assertEquals(TransferFailure.PeerUnreachable(HOST), refused.cause)

        network.failWith = { SocketTimeoutException("read timed out") }
        val timedOut = assertIs<Outcome.Error>(client(devices).pull(SyncArtifact.Passwords, HOST, PORT))
        assertEquals("peer unreachable: read timed out", timedOut.message)
        assertEquals(TransferFailure.PeerUnreachable(HOST), timedOut.cause)

        // ConnectException's sibling under SocketException, and the classic dozing-Wi-Fi-peer
        // error - without this mapping a phone that let its radio sleep failed the *first* sync
        // attempt with no retry at all.
        network.failWith = { NoRouteToHostException("no route to host") }
        val noRoute = assertIs<Outcome.Error>(client(devices).push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT))
        assertEquals("peer unreachable: no route to host", noRoute.message)
        assertEquals(TransferFailure.PeerUnreachable(HOST), noRoute.cause)

        network.failWith = { NoRouteToHostException("no route to host") }
        val noRoutePull = assertIs<Outcome.Error>(client(devices).pull(SyncArtifact.Passwords, HOST, PORT))
        assertEquals("peer unreachable: no route to host", noRoutePull.message)
        assertEquals(TransferFailure.PeerUnreachable(HOST), noRoutePull.cause)

        network.failWith = { IllegalStateException("boom") }
        val general = assertIs<Outcome.Error>(client(devices).push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT))
        assertEquals(TransferFailure.GeneralTransferFailure, general.cause)

        // Cancellation is not a transfer failure: swallowing it into an Outcome would let a cancelled
        // sync report an error state and keep its caller's scope alive.
        network.failWith = { CancellationException("sync cancelled") }
        assertFailsWith<CancellationException> {
            client(devices).push(SyncArtifact.Passwords, PAYLOAD, FILE_NAME, HOST, PORT)
        }
        assertFailsWith<CancellationException> { client(devices).pull(SyncArtifact.Passwords, HOST, PORT) }
    }

    /**
     * The six generic failure strings, one per (artifact, direction). They are the only place the
     * artifact's label surfaces to the user, and the whole point of parameterising one client rather
     * than keeping three services is that these must not drift — including the colon/space quirk of
     * the unlabelled password artifact.
     */
    @Test
    fun errorMessagesKeepEachArtifactsOwnLabel() = runBlocking<Unit> {
        val devices = FakeTrustedDevices(signedDevice())
        network.failWith = { IllegalStateException("boom") }

        val pushMessages = ARTIFACTS.map { artifact ->
            assertIs<Outcome.Error>(client(devices).push(artifact, PAYLOAD, FILE_NAME, HOST, PORT)).message
        }
        val pullMessages = ARTIFACTS.map { artifact ->
            assertIs<Outcome.Error>(client(devices).pull(artifact, HOST, PORT)).message
        }

        assertEquals(
            listOf(
                "error transferring: boom",
                "error transferring pgp bundle: boom",
                "error transferring keystore bundle: boom",
            ),
            pushMessages,
        )
        assertEquals(
            listOf(
                "error pulling: boom",
                "error pulling pgp bundle: boom",
                "error pulling keystore bundle: boom",
            ),
            pullMessages,
        )
    }

    // ------------------------------------------------------------------ empty peers

    @Test
    fun anEmptyOrAbsentPullResponseIsAnEmptySuccess() = runBlocking<Unit> {
        val legacy = FakeTrustedDevices(legacyDevice())
        val signed = FakeTrustedDevices(signedDevice())

        network.pullResponse = { _, _ -> null }
        assertContentEquals(
            ByteArray(0),
            assertIs<Outcome.Success<ByteArray>>(client(legacy).pull(SyncArtifact.Passwords, HOST, PORT)).value,
            "a peer with no artifact yet is not an error",
        )
        assertContentEquals(
            ByteArray(0),
            assertIs<Outcome.Success<ByteArray>>(client(signed).pull(SyncArtifact.Passwords, HOST, PORT)).value,
        )

        network.pullResponse = { _, _ -> ByteArray(0) }
        assertContentEquals(
            ByteArray(0),
            assertIs<Outcome.Success<ByteArray>>(client(legacy).pull(SyncArtifact.Passwords, HOST, PORT)).value,
        )
        assertContentEquals(
            ByteArray(0),
            assertIs<Outcome.Success<ByteArray>>(client(signed).pull(SyncArtifact.Passwords, HOST, PORT)).value,
        )
    }

    // ------------------------------------------------------------------ routes and kinds

    /**
     * The k2k route contract. `Passwords` carries a null upload path on purpose: it is the one
     * artifact that rode k2k's `/upload` default, and [SyncNetwork.K2k] turns that null back into
     * the default route rather than inventing a path here.
     */
    @Test
    fun pushAndPullUseEachArtifactsFrozenRouteAndKind() = runBlocking<Unit> {
        val devices = FakeTrustedDevices(signedDevice())
        network.pullResponse = { _, _ -> null }

        ARTIFACTS.forEach { artifact ->
            assertIs<Outcome.Success<Unit>>(client(devices).push(artifact, PAYLOAD, FILE_NAME, HOST, PORT))
            assertIs<Outcome.Success<ByteArray>>(client(devices).pull(artifact, HOST, PORT))
        }

        assertEquals(listOf(null, "/upload/pgp-keys", "/upload/keystore"), network.uploads.map { it.path })
        assertEquals(listOf("passwords", "pgp-keys", "keystore"), network.pulls.map { it.kind })
        assertNull(SyncArtifact.Passwords.uploadPath, "passwords ride k2k's default upload route")
    }

    // ------------------------------------------------------------------ construction

    private fun client(devices: TrustedDevicesRepository) = ArtifactSyncClient(
        syncTlsProvider = SyncTlsProvider(preferences, devices),
        hybridKeyManager = HybridKeyManager(platform, JvmCryptoService(), preferences, devices),
        mlDsaKeyManager = MlDsaKeyManager(platform, JvmCryptoService(), preferences, devices),
        network = network,
    )

    private suspend fun localMlDsaPublicKey(): ByteArray = assertNotNull(
        MlDsaKeyManager(platform, JvmCryptoService(), preferences, FakeTrustedDevices()).getPublicKeySerialized(),
    )

    private suspend fun localHybridKeyPair(): HybridKem.KeyPair = assertNotNull(
        HybridKeyManager(platform, JvmCryptoService(), preferences, FakeTrustedDevices()).getKeyPair(),
    )

    private fun legacyDevice() = TrustedDevice(
        name = "legacy peer",
        fingerprint = FINGERPRINT,
        lastHost = HOST,
        pairingSecurity = PairingSecurity.LegacyRsa,
    )

    private fun signedDevice() = TrustedDevice(
        name = "upgraded peer",
        fingerprint = FINGERPRINT,
        lastHost = HOST,
        hybridPublicKey = Base64.Default.encode(EnvelopeCodec.serializePublicKey(peerHybrid.publicKey)),
        mldsaPublicKey = Base64.Default.encode(peerMlDsa.publicKey),
        pairingSecurity = PairingSecurity.SignedHybridRequired,
    )

    private fun assertNoNetworkIo() {
        assertTrue(
            network.downloadRequests.isEmpty() && network.uploads.isEmpty() && network.pulls.isEmpty(),
            "expected no network I/O; saw downloads=${network.downloadRequests}, " +
                "uploads=${network.uploads.size}, pulls=${network.pulls.map { it.kind }}",
        )
    }

    /**
     * A signed-in session. [withIdentity] false models "signed in but the identity store never
     * opened", which is the only way a paired host yields a null client TLS.
     */
    private fun startSession(withIdentity: Boolean) {
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        if (withIdentity) {
                            scoped<Key>(named(PRIVATE_DECRYPTION_KEY)) { localRsa.private }
                            scoped<Key>(named(PUBLIC_ENCRYPTION_KEY)) { localRsa.public }
                        }
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                    }
                },
            )
        }
        sessionKey = PasswordVaultCipher().createSession(VAULT_PASSWORD).sessionKey
        runBlocking {
            KoinPlatform.getKoin()
                .getOrCreateScope("session-${preferences.getSessionId()}", named("sessionScope"))
                .get<VaultSession>(named(VAULT_SESSION_HANDLE))
                .bind(sessionKey)
        }
    }

    // ------------------------------------------------------------------ fakes

    private data class RecordedUpload(
        val bytes: ByteArray,
        val fileName: String,
        val host: String,
        val port: Int,
        val path: String?,
    )

    private data class RecordedPull(val kind: String, val clientKey: ByteArray, val host: String, val port: Int)

    /**
     * Records every call and serves scripted answers. It throws [failWith] *after* recording, so the
     * "no network I/O" assertions stay honest on the failure paths too.
     */
    private class FakeSyncNetwork : SyncNetwork {
        val downloadRequests = mutableListOf<String>()
        val uploads = mutableListOf<RecordedUpload>()
        val pulls = mutableListOf<RecordedPull>()
        var pullResponse: ((kind: String, clientKey: ByteArray) -> ByteArray?)? = null
        var failWith: (() -> Throwable)? = null

        private val served = mutableMapOf<String, ByteArray>()

        fun serve(name: String, bytes: ByteArray) {
            served[name] = bytes
        }

        override suspend fun downloadFile(name: String, host: String, port: Int, tls: K2kClientTls): ByteArray? {
            downloadRequests += name
            failWith?.let { throw it() }
            return served[name]
        }

        override suspend fun uploadFile(
            bytes: ByteArray,
            fileName: String,
            host: String,
            port: Int,
            path: String?,
            tls: K2kClientTls,
        ) {
            uploads += RecordedUpload(bytes, fileName, host, port, path)
            failWith?.let { throw it() }
        }

        override suspend fun requestSyncPull(
            kind: String,
            clientKey: ByteArray,
            host: String,
            port: Int,
            tls: K2kClientTls,
        ): ByteArray? {
            pulls += RecordedPull(kind, clientKey, host, port)
            failWith?.let { throw it() }
            return pullResponse?.invoke(kind, clientKey)
        }
    }

    private class FakeTrustedDevices(private val devices: List<TrustedDevice> = emptyList()) : TrustedDevicesRepository {
        constructor(device: TrustedDevice) : this(listOf(device))

        override fun observeAll(): Flow<List<TrustedDevice>> = flowOf(devices)
        override suspend fun getAll(): List<TrustedDevice> = devices
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
        override suspend fun remove(name: String) = Unit
        override suspend fun getByHost(host: String): TrustedDevice? = devices.firstOrNull { it.lastHost == host }
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
        override suspend fun updateHost(name: String, host: String) = Unit
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
        override suspend fun markSignedHybridPairingsForReverification() = Unit
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("password", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "artifact-sync-client-test"
        override suspend fun clear() = Unit
    }

    private companion object {
        const val HOST = "192.0.2.44"

        /**
         * The typed-address refusal. One message covers "nobody is at this address" and "two
         * pairings are", because an address two records claim identifies neither and picking one
         * would pin an arbitrary SPKI - see `unresolvedHostMessage`.
         */
        const val UNRESOLVED = "no single paired device at $HOST - pair it, or pick the device from the sync chooser"
        const val PORT = 2323
        const val FILE_NAME = "staged.db"
        const val FINGERPRINT = "AA:BB:CC:DD"
        const val VAULT_PASSWORD = "artifact-sync-client-password"

        val PAYLOAD = "sender vault".encodeToByteArray()

        /** Frozen order: passwords, pgp, keystore — the message and route assertions index on it. */
        val ARTIFACTS = listOf(SyncArtifact.Passwords, SyncArtifact.PgpKeys, SyncArtifact.Keystore)

        /** One keygen per class; the peer's key material is real, only the socket is not. */
        val localRsa: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val peerHybrid: HybridKem.KeyPair = HybridKem.generateKeyPair()
        val peerMlDsa: MlDsa.KeyPair = MlDsa.generateKeyPair()
    }
}
