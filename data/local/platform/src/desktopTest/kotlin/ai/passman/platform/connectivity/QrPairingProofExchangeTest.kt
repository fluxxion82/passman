package ai.passman.platform.connectivity

import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.PendingPairingState
import ai.passman.domain.connectivity.QrPairingEvent
import ai.passman.domain.connectivity.QrPairingSession
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.repository.FileTransferRepository
import ai.passman.platform.repository.FileTransferRepository.Companion.PAIRING_PORT
import ai.passman.platform.repository.PasswordEntryIdentity
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.tls.SyncTlsProvider
import com.k2k.test.client.uploadPairingBundle
import java.io.File
import java.net.InetAddress
import java.nio.file.Files
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * The shower's half of QR pairing, over the real plaintext pairing listener.
 *
 * Everything between the scanner pressing "pair" and a card appearing on the shower's screen runs
 * here for real: `JvmFingerprintService` pushes with the proof header, k2k's route reads it back out,
 * and `FileTransferRepository` hands bundle + proof + caller host to the [QrPairingSession] the
 * displayed QR armed. What the unit tests on either side cannot see is exactly this seam — a proof
 * that never leaves the pusher, a header k2k drops, or a listener wired to the wrong callback all
 * look like a passing build and a QR that silently never verifies.
 *
 * The proofs below are computed here from `javax.crypto.Mac` and a base64url alphabet spelled out in
 * this file, never by asking the service under test what it would have produced. A proof the
 * implementation checks against its own arithmetic proves only that the arithmetic is repeatable.
 * The verifying test then asserts the real `JvmFingerprintService`, fed the operands
 * `BeginDevicePairing` feeds it, lands on that same hand-rolled string — so the production HMAC is
 * pinned to the wire format rather than only to the verifier that mirrors it.
 *
 * The single-accept slot on the k2k route is the other thing pinned here, because it is shared state
 * an attacker can reach: a failed proof must leave it for the honest peer's retry, and a verified one
 * must burn it so the same push cannot be replayed off the wire.
 */
@OptIn(ExperimentalEncodingApi::class)
class QrPairingProofExchangeTest {

    private lateinit var root: File
    private lateinit var repository: FileTransferRepository
    private lateinit var preferences: FakePreferences
    private lateinit var pendingPairingState: PendingPairingState
    private lateinit var session: QrPairingSession

    /** The real push side: what `BeginDevicePairing` calls once it has computed a proof. */
    private lateinit var scannerPush: JvmFingerprintService

    @BeforeTest
    fun setUp() = runBlocking {
        root = Files.createTempDirectory("qr-pairing-proof").toFile()
        val platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        preferences = FakePreferences()
        val devices = FakeTrustedDevices()
        val crypto = JvmCryptoService()
        val hybridKeyManager = HybridKeyManager(platform, crypto, preferences, devices)
        val mlDsaKeyManager = MlDsaKeyManager(platform, crypto, preferences, devices)
        pendingPairingState = PendingPairingState()
        session = QrPairingSession(
            fingerprintService = ShowerIdentity(SHOWER_BUNDLE),
            pendingPairingState = pendingPairingState,
        )
        repository = FileTransferRepository(
            platform = platform,
            coroutineScopeFacade = NeverRunsTransferScope(),
            coroutinesContextFacade = RealContexts,
            transferEventPersistence = NoopTransferEvents,
            passwordEventPersistence = NoopPasswordEvents,
            passwordDatabaseStorage = JvmPasswordDatabaseStorage(platform),
            pgpEventPersistence = NoopPgpEvents,
            keystoreEventPersistence = NoopKeystoreEvents,
            userPreferences = preferences,
            ipAddressProvider = LoopbackIp,
            syncTlsProvider = SyncTlsProvider(preferences, devices),
            hybridKeyManager = hybridKeyManager,
            mlDsaKeyManager = mlDsaKeyManager,
            vaultCipher = PasswordVaultCipher(crypto),
            entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
            qrPairingSession = session,
        )
        scannerPush = JvmFingerprintService(preferences, hybridKeyManager, mlDsaKeyManager)
        repository.startPairingServer()
    }

    @AfterTest
    fun tearDown() {
        runBlocking { repository.stopPairingServer() }
        root.deleteRecursively()
    }

    @Test
    fun aProofThatVerifiesArmsThePairingAndSpendsTheListenersOneExchange() = withEvents { events ->
        session.register(NONCE, owner())

        // The production HMAC, over the operands `BeginDevicePairing` feeds it — its own bundle
        // first, the fetched one second — must land on the same string this file computes by hand.
        // Without this line every proof in the suite is checked only against arithmetic the
        // implementation also performs, so flipping the concatenation order (or the key) on both
        // sides of the protocol at once would keep every test green while no shipped pair of
        // devices could ever agree.
        assertEquals(
            proof(NONCE),
            PROOF_BASE64.encode(
                scannerPush.hmacSha256(
                    key = NONCE,
                    data = SCANNER_BUNDLE.canonicalEncoding() + SHOWER_BUNDLE.canonicalEncoding(),
                ),
            ),
            "the real fingerprint service must produce the proof this test hand-rolls",
        )

        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proof(NONCE)),
        )

        val verified = assertIs<QrPairingEvent.VerifiedInbound>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertTrue(
            InetAddress.getByName(verified.peerAddress).isLoopbackAddress,
            "the event must carry the address the push actually came from, got '${verified.peerAddress}'",
        )
        val pending = assertNotNull(
            pendingPairingState.active(owner()),
            "a verified proof is what arms the card the user confirms",
        )
        assertTrue(pending.verifiedViaQr, "and it is marked verified so the screen drops the manual compare")
        assertEquals(verified.peerAddress, pending.peerAddress)
        assertEquals(verified.safetyNumber, pending.safetyNumber)

        // Replayed off the wire: the same bytes, the same header, and now the slot is gone.
        val replay = assertFailsWith<IllegalStateException> {
            uploadPairingBundle(wireBundle(SCANNER_BUNDLE), LOOPBACK, PAIRING_PORT, proof(NONCE))
        }
        assertTrue(
            replay.message.orEmpty().contains("409"),
            "the verified exchange must burn the single-accept slot, got '${replay.message}'",
        )
        assertTrue(events.tryReceive().isFailure, "a refused replay is not announced to the screen")
    }

    @Test
    fun aProofThatFailsIsReportedAndLeavesTheSlotForTheHonestRetry() = withEvents { events ->
        session.register(NONCE, owner())

        // Keyed on a nonce this device never showed: what someone who only reached the plaintext
        // port can produce.
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proof(WRONG_NONCE)),
        )

        assertIs<QrPairingEvent.ProofFailed>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertNull(pendingPairingState.active(owner()), "a proof that did not hold up arms nothing")

        // The honest scanner retries against the same QR, which is still on screen.
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proof(NONCE)),
        )

        assertIs<QrPairingEvent.VerifiedInbound>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertNotNull(
            pendingPairingState.active(owner()),
            "a failed proof must not let anyone spend the exchange the honest peer still needs",
        )
    }

    @Test
    fun aPushWithNoProofHeaderAtAllIsReportedAndLeavesTheSlotForTheHonestRetry() = withEvents { events ->
        session.register(NONCE, owner())

        // An app from before QR pairing existed, pushing while the QR happens to be on screen: it
        // sends no header at all rather than a wrong one. This must reach the same fallback as a bad
        // proof — a route that rejected the header-less request outright, or a listener that read a
        // missing header as "nothing to check", would both leave the user staring at a QR that never
        // resolves.
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proofBase64Url = null),
        )

        assertIs<QrPairingEvent.ProofFailed>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertNull(pendingPairingState.active(owner()), "a push that proved nothing arms nothing")

        // And the QR is still live: the user updates the old device, or the right one scans.
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proof(NONCE)),
        )

        assertIs<QrPairingEvent.VerifiedInbound>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertNotNull(
            pendingPairingState.active(owner()),
            "a proofless push must not spend the exchange the honest peer still needs",
        )
    }

    @Test
    fun anUninvitedPushIsSwallowedWithoutArmingAnythingOrSpendingTheExchange() = withEvents { events ->
        // No QR on screen: the pre-QR behaviour, where the push is dropped and answered identically
        // so a prober on the plaintext port learns nothing.
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT),
        )
        assertNull(pendingPairingState.active(owner()))

        // The user now shows the QR and the real scanner arrives. That this lands at all is the
        // assertion: an ignored push must not have spent the listener's one exchange, and the event
        // it produces is the first thing the screen hears about — the drop above said nothing.
        session.register(NONCE, owner())
        assertIs<Outcome.Success<*>>(
            scannerPush.pushDeviceIdentityBundle(SCANNER_BUNDLE, LOOPBACK, PAIRING_PORT, proof(NONCE)),
        )

        assertIs<QrPairingEvent.VerifiedInbound>(withTimeout(EVENT_TIMEOUT_MS) { events.receive() })
        assertNotNull(pendingPairingState.active(owner()))
    }

    // ------------------------------------------------------------------ helpers

    private suspend fun owner() = PairingOwner.current(preferences)

    /**
     * The proof the scanner sends: HMAC-SHA256 keyed on the QR's nonce over the scanner's canonical
     * bundle followed by the shower's, base64url with no padding.
     *
     * Spelled out here from `javax.crypto.Mac` and the alphabet the wire format names, rather than
     * borrowed from the production codec, so a change to either side of the protocol has to be made
     * twice before these tests agree with it.
     */
    private fun proof(nonce: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(nonce, "HmacSHA256")) }
        return PROOF_BASE64.encode(mac.doFinal(SCANNER_BUNDLE.canonicalEncoding() + SHOWER_BUNDLE.canonicalEncoding()))
    }

    private fun wireBundle(bundle: DeviceIdentityBundle): ByteArray =
        Json.encodeToString(bundle).encodeToByteArray()

    /**
     * Runs [block] with a live subscriber on the session's event flow.
     *
     * The flow replays nothing, so a collector attached after the push would miss the event it is
     * waiting for; `onSubscription` is what makes "the collector is attached" something to await
     * rather than something to sleep for.
     */
    private fun withEvents(block: suspend CoroutineScope.(ReceiveChannel<QrPairingEvent>) -> Unit) = runBlocking {
        val events = Channel<QrPairingEvent>(Channel.UNLIMITED)
        val subscribed = CompletableDeferred<Unit>()
        val collector = launch(Dispatchers.Default) {
            session.events
                .onSubscription { subscribed.complete(Unit) }
                .collect { events.send(it) }
        }
        subscribed.await()
        try {
            block(events)
        } finally {
            collector.cancel()
        }
    }

    // ------------------------------------------------------------------ fakes

    /** The shower's own identity, which is all [QrPairingSession] asks the platform seam for. */
    private class ShowerIdentity(private val own: DeviceIdentityBundle) : FingerprintService {
        override fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

        override fun randomBytes(count: Int): ByteArray = error("the listener side draws no randomness")

        override fun fingerprintOf(publicKeyBytes: ByteArray): String =
            digest(publicKeyBytes).joinToString(":") { "%02X".format(it.toInt() and 0xFF) }

        override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = Outcome.Success(own)

        override suspend fun getOwnFingerprint(): Outcome<String> = Outcome.Success(fingerprintOf(own.rsaSpki))

        override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> =
            error("the listener side fetches nothing")

        override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
            error("the listener side fetches nothing")

        override suspend fun pushDeviceIdentityBundle(
            bundle: DeviceIdentityBundle,
            host: String,
            port: Int,
            proofBase64Url: String?,
        ): Outcome<Unit> = error("the listener side pushes nothing")
    }

    /** A transfer scope whose dispatcher drops every task: the pairing listener must not need it. */
    private class NeverRunsTransferScope : CoroutineScopeFacade {
        private val neverDispatcher = object : kotlinx.coroutines.CoroutineDispatcher() {
            override fun dispatch(context: CoroutineContext, block: Runnable) = Unit
        }
        override val globalScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        override var transferScope = CoroutineScope(neverDispatcher + SupervisorJob())
    }

    private object RealContexts : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.IO
        override val main: CoroutineContext = Dispatchers.Default
        override val default: CoroutineContext = Dispatchers.Default
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Default
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("hash", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "qr-pairing-proof"
        override suspend fun clear() = Unit
    }

    private class FakeTrustedDevices : TrustedDevicesRepository {
        override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
        override suspend fun getAll(): List<TrustedDevice> = emptyList()
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
        override suspend fun remove(name: String) = Unit
        override suspend fun getByHost(host: String): TrustedDevice? = null
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
        override suspend fun updateHost(name: String, host: String) = Unit
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
        override suspend fun markSignedHybridPairingsForReverification() = Unit
    }

    private object NoopTransferEvents : TransferEventPersistence {
        override fun events(): Flow<TransferEvent> = emptyFlow()
        override suspend fun update(event: TransferEvent) = Unit
    }

    private object NoopPasswordEvents : PasswordEventPersistence {
        override fun events(): Flow<PasswordEvent> = emptyFlow()
        override suspend fun update(event: PasswordEvent) = Unit
    }

    private object NoopPgpEvents : PgpEventPersistence {
        override fun events(): Flow<PgpEvent> = emptyFlow()
        override suspend fun update(event: PgpEvent) = Unit
    }

    private object NoopKeystoreEvents : KeystoreEventPersistence {
        override fun events(): Flow<KeystoreEvent> = emptyFlow()
        override suspend fun update(event: KeystoreEvent) = Unit
    }

    private object LoopbackIp : IpAddressProvider {
        override suspend fun getLocalIpAddress(): String = "127.0.0.1"
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val EVENT_TIMEOUT_MS = 5_000L

        /** The frozen wire encoding for the proof header, spelled out rather than imported. */
        val PROOF_BASE64: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        val NONCE = ByteArray(32) { (it + 1).toByte() }
        val WRONG_NONCE = ByteArray(32) { (it + 101).toByte() }

        val SHOWER_BUNDLE = identityBundle(0x11)
        val SCANNER_BUNDLE = identityBundle(0x22)

        private fun identityBundle(seed: Int): DeviceIdentityBundle = DeviceIdentityBundle(
            rsaSpki = ByteArray(294) { seed.toByte() },
            hybridPublicKey = ByteArray(32 + 2 + 1_184) { seed.toByte() }.also {
                it[32] = (1_184 ushr 8).toByte()
                it[33] = 1_184.toByte()
            },
            mldsaPublicKey = ByteArray(1_952) { seed.toByte() },
            capabilityBits = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
        )
    }
}
