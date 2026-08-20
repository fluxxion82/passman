package ai.passman.platform.transfer

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.HybridKem
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.MlDsa
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.impl.LocalTrustedDevicesRepository
import ai.passman.platform.repository.FileTransferRepository
import ai.passman.platform.repository.PasswordEntryIdentity
import ai.passman.platform.repository.unarmedQrPairingSession
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.repo.tls.TlsIdentity
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
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
import ai.passman.domain.user.persistences.InMemoryUserEventsPersistence
import ai.passman.domain.user.repository.UserPreferences
import com.k2k.test.server.startServer
import com.k2k.test.tls.K2kServerTls
import com.russhwolf.settings.MapSettings
import java.io.File
import java.io.IOException
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.CoroutineContext
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * Task 9's policy, end to end: after a pairing is upgraded to `SignedHybridRequired`, sync uses
 * only the peer keys persisted at pairing — nothing fetched over the wire — and every inbound
 * payload must be a suite-4 envelope signed by exactly the stored ML-DSA key. `LegacyRsa` pairings
 * keep today's behaviour byte for byte, and `AwaitingConfirmation` (a previously-signed pairing
 * whose peer identity went stale) is refused in both directions rather than silently downgraded.
 *
 * Receive-side policy is driven through the real [FileTransferRepository] handlers with the caller
 * pin the k2k server threads through; sender-side policy is driven through the real
 * [JvmPasswordTransferService] against a live mTLS k2k server on the loopback, so "never fetches
 * keys over the wire" is observed on an actual socket, not inferred from a mock.
 */
@OptIn(ExperimentalEncodingApi::class)
class SignedHybridSyncPolicyTest {
    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var vaultCipher: PasswordVaultCipher
    private lateinit var sessionKey: VaultSessionKey
    private val preferences = TestPreferences()
    private var server: io.ktor.server.engine.EmbeddedServer<*, *>? = null

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("signed-hybrid-policy").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        storage = JvmPasswordDatabaseStorage(platform)
        vaultCipher = PasswordVaultCipher(JvmCryptoService())
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped<java.security.Key>(named(PRIVATE_DECRYPTION_KEY)) { localRsa.private }
                        scoped<java.security.Key>(named(PUBLIC_ENCRYPTION_KEY)) { localRsa.public }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { CryptoKey(localRsa.private) }
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                    }
                },
            )
        }
        sessionKey = vaultCipher.createSession("signed-hybrid-policy-password").sessionKey
        runBlocking {
            KoinPlatform.getKoin()
                .getOrCreateScope("session-${preferences.getSessionId()}", named("sessionScope"))
                .get<VaultSession>(named(VAULT_SESSION_HANDLE))
                .bind(sessionKey)
        }
    }

    @AfterTest
    fun tearDown() {
        server?.stop(0, 0)
        server = null
        stopKoin()
        root.deleteRecursively()
    }

    // ------------------------------------------------------------------ transport-material policy

    @Test
    fun clientTls_allowsOnlyLegacyAndSignedPairings() = runBlocking<Unit> {
        PairingSecurity.entries.forEach { security ->
            val devices = trustedDevices()
            devices.add(
                TrustedDevice(
                    name = security.name,
                    fingerprint = "AA:BB",
                    lastHost = "192.0.2.44",
                    pairingSecurity = security,
                ),
                PairingOwner.current(preferences),
            )

            val clientTls = SyncTlsProvider(preferences, devices).clientTls("192.0.2.44")
            when (security) {
                PairingSecurity.LegacyRsa -> assertNotNull(clientTls)
                PairingSecurity.AwaitingConfirmation -> assertNull(clientTls)
                PairingSecurity.SignedHybridRequired -> assertNotNull(clientTls)
            }
        }
    }

    @Test
    fun authorize_deniesEveryOpToAnAwaitingConfirmationCaller() = runBlocking<Unit> {
        PairingSecurity.entries.forEach { security ->
            val devices = trustedDevices()
            devices.add(
                TrustedDevice(
                    name = security.name,
                    fingerprint = "AA:BB:CC:DD",
                    lastHost = "192.0.2.44",
                    // Plausible stored PQ keys on purpose: their presence must not count as verified.
                    hybridPublicKey = Base64.Default.encode(serializedHybrid(peerHybrid)),
                    mldsaPublicKey = Base64.Default.encode(peerMlDsa.publicKey),
                    pairingSecurity = security,
                ),
                PairingOwner.current(preferences),
            )
            val provider = SyncTlsProvider(preferences, devices)

            val expected = when (security) {
                PairingSecurity.LegacyRsa, PairingSecurity.SignedHybridRequired -> true
                PairingSecurity.AwaitingConfirmation -> false
            }
            assertEquals(expected, provider.authorize(SyncOps.PASSWORDS, "aabbccdd"), security.name)
            assertEquals(
                expected,
                provider.authorize("download/hybridPublicKey", "aabbccdd"),
                "$security: even public-key downloads are denied until re-confirmed",
            )
        }
    }

    // ------------------------------------------------------------------ real repository transition

    @Test
    fun realRepository_marksOnlySignedHybridPairingsAsAwaitingConfirmation() = runBlocking<Unit> {
        val devices = trustedDevices()
        val owner = PairingOwner.current(preferences)
        devices.add(TrustedDevice("legacy", "01:02", "192.0.2.1", pairingSecurity = PairingSecurity.LegacyRsa), owner)
        devices.add(
            TrustedDevice("signed", "03:04", "192.0.2.2", pairingSecurity = PairingSecurity.SignedHybridRequired),
            owner,
        )
        devices.add(
            TrustedDevice("already-stale", "05:06", "192.0.2.3", pairingSecurity = PairingSecurity.AwaitingConfirmation),
            owner,
        )

        devices.markSignedHybridPairingsForReverification()

        val byName = devices.getAll().associateBy { it.name }
        assertEquals(PairingSecurity.LegacyRsa, byName.getValue("legacy").pairingSecurity)
        assertEquals(PairingSecurity.AwaitingConfirmation, byName.getValue("signed").pairingSecurity)
        assertEquals(PairingSecurity.AwaitingConfirmation, byName.getValue("already-stale").pairingSecurity)
    }

    // ------------------------------------------------------------------ receive side: uploads

    @Test
    fun signedHybridSender_validV4SignedByItsStoredKey_isAcceptedAndImported() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(signedSenderDevice()))
        val localHybrid = localHybridPublicKey()
        val payload = "peer vault".encodeToByteArray()

        repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybrid, peerMlDsa), STAGED, SENDER_PIN)

        assertContentEquals(payload, storedVault())
    }

    @Test
    fun signedHybridSender_unsignedV3ThatWouldDecryptCleanly_isRejectedBeforeStaging() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(signedSenderDevice()))
        val localHybrid = localHybridPublicKey()
        val v3 = EnvelopeCodec.encryptHybrid("downgrade".encodeToByteArray(), localHybrid)
        // Fixture control: the envelope is genuinely decryptable — the rejection under test is
        // about the missing signature, not about damage.
        assertContentEquals("downgrade".encodeToByteArray(), HybridKem.decrypt(v3, localHybridPrivate()))

        assertFailsWith<IllegalArgumentException> { repo.processUploadedFile(v3, STAGED, SENDER_PIN) }

        assertNothingStaged()
    }

    @Test
    fun signedHybridSender_validV4SignedByADifferentValidKey_isRejectedBeforeStaging() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(signedSenderDevice()))
        // Well-formed, correctly signed — by an impostor's valid key, not the stored one.
        val impostor = EnvelopeCodec.encryptHybrid(
            "impostor".encodeToByteArray(),
            localHybridPublicKey(),
            MlDsa.generateKeyPair(),
        )

        assertFailsWith<IllegalArgumentException> { repo.processUploadedFile(impostor, STAGED, SENDER_PIN) }

        assertNothingStaged()
    }

    @Test
    fun awaitingConfirmationSender_withPlausibleStoredKeys_isRefusedEvenAValidlySignedPayload() = runBlocking<Unit> {
        // The device still carries real PQ keys — Task 7 Step 2b keeps them persisted — and the
        // payload verifies against them. They are not treated as verified anyway.
        val repo = repository(
            FakeTrustedDevices(signedSenderDevice().copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)),
        )
        val env = EnvelopeCodec.encryptHybrid("stale".encodeToByteArray(), localHybridPublicKey(), peerMlDsa)

        val failure = assertFailsWith<IllegalStateException> { repo.processUploadedFile(env, STAGED, SENDER_PIN) }

        assertTrue(failure.message.orEmpty().contains("re-verification"), "refusal must name the recovery path")
        assertNothingStaged()
    }

    /**
     * k2k answers the pushing peer `200` exactly when this call returns normally, and `500` when it
     * throws. So a vault write that fails has to fail *here*, before the response — with the write
     * inside a launched coroutine the peer was told its vault had landed while the write was still
     * pending, and if it then failed the peer had already recorded a successful sync and would not
     * send again. A silent write failure on the receiving device is indistinguishable, to the
     * sender, from a completed sync.
     */
    @Test
    fun aVaultWriteThatFailsIsReportedToThePeerInsteadOfAnsweredWithSuccess() = runBlocking<Unit> {
        val repo = repository(
            FakeTrustedDevices(legacySenderDevice()),
            passwordStorage = FailingWriteStorage(storage),
        )
        val payload = "a vault the receiver cannot store".encodeToByteArray()

        assertFailsWith<IOException> {
            repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybridPublicKey()), STAGED, SENDER_PIN)
        }
    }

    /**
     * Two records can share a fingerprint: it is the peer's long-term identity, not a property of
     * the pairing ceremony, so re-pairing one physical device under a new name leaves both. The pin
     * on the wire then matches both, and a first-match lookup picked the decryption POLICY by
     * accident — accepting an unsigned legacy envelope because the older record said LegacyRsa,
     * while the newer one demanded a signed hybrid. That is a silent downgrade of the boundary
     * pairing exists to hold, so an ambiguous pin is refused instead.
     */
    @Test
    fun anAmbiguousSenderPinIsRefusedRatherThanResolvedToOneOfTheRecords() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice(), signedSenderDevice()))
        val legacyEnvelope = EnvelopeCodec.encryptHybrid("legacy v3 vault".encodeToByteArray(), localHybridPublicKey())

        val failure = assertFailsWith<IllegalStateException> {
            repo.processUploadedFile(legacyEnvelope, STAGED, SENDER_PIN)
        }

        assertTrue(
            failure.message.orEmpty().contains("2 pairings"),
            "the refusal must name the ambiguity, since the fix is to remove a duplicate pairing " +
                "rather than to pair the device: ${failure.message}",
        )
        assertNothingStaged()
    }

    @Test
    fun anAmbiguousSenderPinIsRefusedEvenWhenBothRecordsWouldAllowThePayload() = runBlocking<Unit> {
        // Both LegacyRsa, so no policy disagreement — still refused. Whether the records happen to
        // agree today is not something the receive side can rely on, and a rule that only applies
        // when it would have mattered is a rule nobody can reason about.
        val duplicate = legacySenderDevice().copy(name = "legacy peer (re-paired)")
        val repo = repository(FakeTrustedDevices(legacySenderDevice(), duplicate))
        val legacyEnvelope = EnvelopeCodec.encryptHybrid("legacy v3 vault".encodeToByteArray(), localHybridPublicKey())

        assertFailsWith<IllegalStateException> {
            repo.processUploadedFile(legacyEnvelope, STAGED, SENDER_PIN)
        }
    }

    @Test
    fun legacyRsaSender_unsignedV3_isAcceptedExactlyAsToday() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice()))
        val payload = "legacy v3 vault".encodeToByteArray()

        repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybridPublicKey()), STAGED, SENDER_PIN)

        assertContentEquals(payload, storedVault())
    }

    @Test
    fun legacyRsaSender_classicalV2_isAcceptedExactlyAsToday() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice()))
        val payload = "legacy v2 vault".encodeToByteArray()

        repo.processUploadedFile(JvmCryptoService().encryptBytes(payload, CryptoKey(localRsa.public)), STAGED, SENDER_PIN)

        assertContentEquals(payload, storedVault())
    }

    @Test
    fun successfulSignedTransferFromALegacySender_doesNotPromoteThePairing() = runBlocking<Unit> {
        val devices = FakeTrustedDevices(legacySenderDevice())
        val repo = repository(devices)
        val payload = "signed but legacy".encodeToByteArray()

        // A v4 from a legacy peer is accepted (verified against its own embedded key, as today) —
        // and must change nothing about the stored pairing.
        repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybridPublicKey(), peerMlDsa), STAGED, SENDER_PIN)

        assertContentEquals(payload, storedVault())
        assertEquals(0, devices.writes, "a successful PQ transfer must never write the trusted-device store")
        assertEquals(PairingSecurity.LegacyRsa, devices.getAll().single().pairingSecurity)
    }

    @Test
    fun unknownOrMissingCallerPin_isRejectedBeforeAnyDecryptOrStaging() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice()))
        val env = EnvelopeCodec.encryptHybrid("who sent this".encodeToByteArray(), localHybridPublicKey())

        assertFailsWith<IllegalStateException> { repo.processUploadedFile(env, STAGED, null) }
        assertFailsWith<IllegalStateException> { repo.processUploadedFile(env, STAGED, "deadbeef") }

        assertNothingStaged()
    }

    /**
     * The conflict half of the receive handler, previously untested. An upload landing on a
     * non-empty vault must not import: the payload is staged — sealed as suite 5 under the *local*
     * session key, exactly what `executeReconcileAction` will read — the vault stays byte-identical,
     * and the transfer event says `conflict = true` so the UI offers the reconcile choice. The file
     * name is the *sender's* (`staged-db`, not this user's hash): the receive path stages under the
     * name it was given, and the local vault is addressed through the storage interface only.
     */
    @Test
    fun uploadOntoANonEmptyVault_isStagedForReconcileAndTheVaultIsUntouched() = runBlocking<Unit> {
        val localVault = vaultCipher.encryptVault("the local vault".encodeToByteArray(), sessionKey)
        storage.create(USER, localVault)
        val events = RecordingTransferEvents()
        val repo = repository(FakeTrustedDevices(legacySenderDevice()), transferEvents = events)
        val payload = "peer vault awaiting reconcile".encodeToByteArray()

        repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybridPublicKey()), STAGED, SENDER_PIN)

        assertContentEquals(localVault, storage.read(USER), "a conflicting upload must never touch the vault")
        val staged = File(root, "database/tmp/$STAGED")
        assertTrue(staged.isFile, "the payload must be staged under the sender's file name")
        assertContentEquals(
            payload,
            vaultCipher.decryptVault(staged.readBytes(), sessionKey) { null }.plaintext,
            "staged as suite 5 under the local session key - the format a reconcile read expects",
        )
        assertEquals(
            listOf<TransferEvent>(TransferEvent.PassFileReceived(conflict = true)),
            events.recorded,
            "the UI's reconcile prompt hangs off this event",
        )
    }

    /**
     * The no-conflict half's bookkeeping. That the payload lands in the *local* user's vault —
     * whatever file name the sender used — is asserted by every accept test above via `storedVault()`;
     * this adds what they leave open: the staging area is empty afterwards, no file named after the
     * sender appears in `database/`, and the event reports `conflict = false`.
     */
    @Test
    fun uploadOntoAnEmptyVault_importsAndLeavesNoStagedCopyBehind() = runBlocking<Unit> {
        val events = RecordingTransferEvents()
        val repo = repository(FakeTrustedDevices(legacySenderDevice()), transferEvents = events)
        val payload = "imported directly".encodeToByteArray()

        repo.processUploadedFile(EnvelopeCodec.encryptHybrid(payload, localHybridPublicKey()), STAGED, SENDER_PIN)

        assertContentEquals(payload, storedVault())
        assertTrue(
            File(root, "database/tmp").listFiles().isNullOrEmpty(),
            "an imported payload must not also linger in the staging area",
        )
        assertNull(
            File(root, "database").listFiles()?.firstOrNull { it.name.contains(STAGED) },
            "the sender's file name must never become a vault file of its own",
        )
        assertEquals(listOf<TransferEvent>(TransferEvent.PassFileReceived(conflict = false)), events.recorded)
    }

    @Test
    fun signedHybridPolicy_alsoGatesPgpAndKeystoreUploads() = runBlocking<Unit> {
        val signedRepo = repository(FakeTrustedDevices(signedSenderDevice()))
        val v3 = EnvelopeCodec.encryptHybrid("bundle".encodeToByteArray(), localHybridPublicKey())
        assertFailsWith<IllegalArgumentException> { signedRepo.processPgpKeysUploaded(v3, "pgp", SENDER_PIN) }

        val staleRepo = repository(
            FakeTrustedDevices(signedSenderDevice().copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)),
        )
        val v4 = EnvelopeCodec.encryptHybrid("bundle".encodeToByteArray(), localHybridPublicKey(), peerMlDsa)
        assertFailsWith<IllegalStateException> { staleRepo.processKeystoreUploaded(v4, "keystore", SENDER_PIN) }
    }

    // ------------------------------------------------------------------ receive side: sync pulls

    @Test
    fun signedHybridCaller_pullResponseUsesTheStoredKey_notTheWireKey_andIsSigned() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(signedSenderDevice()))
        val payload = "vault for peer".encodeToByteArray()
        storage.create(USER, vaultCipher.encryptVault(payload, sessionKey))
        // Substitution attempt: the wire carries an attacker key instead of the paired device's.
        val attackerHybrid = HybridKem.generateKeyPair()

        val response = assertNotNull(
            repo.providePasswordSyncPull(serializedHybrid(attackerHybrid), SENDER_PIN),
        )

        assertEquals(4, response[5], "pull responses to an upgraded peer must be signed (suite 4)")
        assertFailsWith<Exception>("the wire-substituted key must NOT be able to open the response") {
            HybridKem.decrypt(response, attackerHybrid.privateKey)
        }
        val localSignerKey = assertNotNull(mlDsaManager(FakeTrustedDevices()).getPublicKeySerialized())
        assertContentEquals(
            payload,
            EnvelopeCodec.decryptSignedHybrid(response, peerHybrid.privateKey, localSignerKey),
            "the response must open with the STORED peer key and verify against the local signer",
        )
    }

    @Test
    fun legacyCaller_pullResponseStillEncryptsToTheWireKey() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice()))
        val payload = "vault for legacy peer".encodeToByteArray()
        storage.create(USER, vaultCipher.encryptVault(payload, sessionKey))
        val wireHybrid = HybridKem.generateKeyPair()

        val response = assertNotNull(repo.providePasswordSyncPull(serializedHybrid(wireHybrid), SENDER_PIN))

        assertContentEquals(payload, HybridKem.decrypt(response, wireHybrid.privateKey))
    }

    @Test
    fun awaitingConfirmationCaller_isRefusedSyncPull() = runBlocking<Unit> {
        val repo = repository(
            FakeTrustedDevices(signedSenderDevice().copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)),
        )
        storage.create(USER, vaultCipher.encryptVault("vault".encodeToByteArray(), sessionKey))

        assertFailsWith<IllegalStateException> {
            repo.providePasswordSyncPull(serializedHybrid(peerHybrid), SENDER_PIN)
        }
    }

    @Test
    fun unknownCallerPin_isRefusedSyncPull() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(legacySenderDevice()))
        storage.create(USER, vaultCipher.encryptVault("vault".encodeToByteArray(), sessionKey))

        assertFailsWith<IllegalStateException> {
            repo.providePasswordSyncPull(serializedHybrid(peerHybrid), "deadbeef")
        }
        assertFailsWith<IllegalStateException> {
            repo.providePasswordSyncPull(serializedHybrid(peerHybrid), null)
        }
    }

    @Test
    fun signedHybridCaller_pgpPullAlsoUsesTheStoredKey() = runBlocking<Unit> {
        val repo = repository(FakeTrustedDevices(signedSenderDevice()))
        File(root, "pgp/$USER").apply { mkdirs() }.resolve("key.asc").writeText("pgp key material")
        val attackerHybrid = HybridKem.generateKeyPair()

        val response = assertNotNull(repo.providePgpSyncPull(serializedHybrid(attackerHybrid), SENDER_PIN))

        val localSignerKey = assertNotNull(mlDsaManager(FakeTrustedDevices()).getPublicKeySerialized())
        assertTrue(
            EnvelopeCodec.decryptSignedHybrid(response, peerHybrid.privateKey, localSignerKey).isNotEmpty(),
            "the pgp bundle must open with the stored peer key",
        )
        assertFailsWith<Exception> { HybridKem.decrypt(response, attackerHybrid.privateKey) }
    }

    // ------------------------------------------------------------------ sender side, over a live server

    @Test
    fun signedHybridPush_usesStoredKeysAndFetchesNothingOverTheWire() = runBlocking<Unit> {
        val net = startPeerServer(servedHybridKey = serializedHybrid(HybridKem.generateKeyPair())) // decoy
        val devices = FakeTrustedDevices(peerServerDevice(PairingSecurity.SignedHybridRequired))
        val service = passwordTransferService(devices)

        val outcome = service.transferDatabaseBytes("sender vault".encodeToByteArray(), STAGED, HOST, net.port)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertTrue(
            net.requests.none { it == "download/hybridPublicKey" || it == "download/mldsaPublicKey" },
            "an upgraded pairing must not fetch key material over the wire; saw ${net.requests}",
        )
        val upload = net.uploads.single()
        assertEquals(SENDER_TLS_PIN, upload.pin, "the mTLS pin must identify the sending device end to end")
        assertEquals(4, upload.bytes[5], "an upgraded pairing must always sign (suite 4)")
        val senderSignerKey = assertNotNull(mlDsaManager(devices).getPublicKeySerialized())
        assertContentEquals(
            "sender vault".encodeToByteArray(),
            EnvelopeCodec.decryptSignedHybrid(upload.bytes, peerHybrid.privateKey, senderSignerKey),
            "the envelope must open with the STORED peer key — not the decoy served on the wire",
        )
        assertEquals(0, devices.writes, "a successful signed transfer must not touch the pairing record")
    }

    @Test
    fun legacyPush_stillFetchesPeerKeysOverTheWire_exactlyAsToday() = runBlocking<Unit> {
        val net = startPeerServer(servedHybridKey = serializedHybrid(peerHybrid), servedMlDsaKey = peerMlDsa.publicKey)
        val devices = FakeTrustedDevices(
            peerServerDevice(PairingSecurity.LegacyRsa).copy(hybridPublicKey = null, mldsaPublicKey = null),
        )
        val service = passwordTransferService(devices)

        val outcome = service.transferDatabaseBytes("legacy vault".encodeToByteArray(), STAGED, HOST, net.port)

        assertIs<Outcome.Success<Unit>>(outcome)
        assertTrue("download/hybridPublicKey" in net.requests, "legacy sync keeps fetching the peer key")
        val upload = net.uploads.single()
        assertContentEquals(
            "legacy vault".encodeToByteArray(),
            HybridKem.decrypt(upload.bytes, peerHybrid.privateKey),
        )
        assertEquals(0, devices.writes, "a successful transfer must never promote a legacy pairing")
        assertEquals(PairingSecurity.LegacyRsa, devices.getAll().single().pairingSecurity)
    }

    @Test
    fun awaitingConfirmationPeer_isRefusedInBothDirections_beforeAnyNetworkIo() = runBlocking<Unit> {
        val net = startPeerServer(servedHybridKey = serializedHybrid(peerHybrid))
        val device = peerServerDevice(PairingSecurity.AwaitingConfirmation)
        val devices = FakeTrustedDevices(device)
        val service = passwordTransferService(devices)

        val push = service.transferDatabaseBytes("refused".encodeToByteArray(), STAGED, HOST, net.port)
        val pull = service.pullDatabase(device, net.port)

        assertTrue(assertIs<Outcome.Error>(push).message.contains("re-verification"))
        assertTrue(assertIs<Outcome.Error>(pull).message.contains("re-verification"))
        assertEquals(emptyList(), net.requests, "a refused pairing must cause no network I/O at all")
        assertEquals(emptyList<Upload>(), net.uploads)
    }

    @Test
    fun signedHybridPull_verifiesAgainstTheStoredKey_withoutWireKeyFetch() = runBlocking<Unit> {
        val payload = "pulled vault".encodeToByteArray()
        val net = startPeerServer(
            servedMlDsaKey = peerMlDsa.publicKey,
            pullResponse = { wireKey ->
                EnvelopeCodec.encryptHybrid(payload, EnvelopeCodec.deserializePublicKey(wireKey), peerMlDsa)
            },
        )
        val device = peerServerDevice(PairingSecurity.SignedHybridRequired)
        val service = passwordTransferService(FakeTrustedDevices(device))

        val outcome = service.pullDatabase(device, net.port)

        assertContentEquals(payload, assertIs<Outcome.Success<ByteArray>>(outcome).value)
        assertTrue(
            net.requests.none { it == "download/mldsaPublicKey" },
            "the verification key must come from the pairing record, not the wire; saw ${net.requests}",
        )
    }

    @Test
    fun signedHybridPull_rejectsAResponseSignedByADifferentKey() = runBlocking<Unit> {
        val net = startPeerServer(
            pullResponse = { wireKey ->
                EnvelopeCodec.encryptHybrid(
                    "forged".encodeToByteArray(),
                    EnvelopeCodec.deserializePublicKey(wireKey),
                    MlDsa.generateKeyPair(), // valid key, wrong identity
                )
            },
        )
        val device = peerServerDevice(PairingSecurity.SignedHybridRequired)
        val service = passwordTransferService(FakeTrustedDevices(device))

        assertIs<Outcome.Error>(service.pullDatabase(device, net.port))
    }

    @Test
    fun signedHybridPull_rejectsAnUnsignedV3Response() = runBlocking<Unit> {
        val net = startPeerServer(
            pullResponse = { wireKey ->
                EnvelopeCodec.encryptHybrid("unsigned".encodeToByteArray(), EnvelopeCodec.deserializePublicKey(wireKey))
            },
        )
        val device = peerServerDevice(PairingSecurity.SignedHybridRequired)
        val service = passwordTransferService(FakeTrustedDevices(device))

        assertIs<Outcome.Error>(service.pullDatabase(device, net.port))
    }

    @Test
    fun signedHybridPgpAndKeystorePush_alsoUseStoredKeysOnly() = runBlocking<Unit> {
        val net = startPeerServer(servedHybridKey = serializedHybrid(HybridKem.generateKeyPair())) // decoy
        val device = peerServerDevice(PairingSecurity.SignedHybridRequired)
        val devices = FakeTrustedDevices(device)
        val syncTls = SyncTlsProvider(preferences, devices)
        val hybrid = hybridManager(devices)
        val mldsa = mlDsaManager(devices)
        val senderSignerKey = assertNotNull(mldsa.getPublicKeySerialized())

        val pgp = JvmPgpTransferService(syncClient(syncTls, hybrid, mldsa))
            .transferPgpBundle("pgp bundle".encodeToByteArray(), "pgp", device, net.port)
        val keystore = JvmKeystoreTransferService(syncClient(syncTls, hybrid, mldsa))
            .transferKeystoreBundle("keystore bundle".encodeToByteArray(), "ks", device, net.port)

        assertIs<Outcome.Success<Unit>>(pgp)
        assertIs<Outcome.Success<Unit>>(keystore)
        assertTrue(net.requests.none { it.startsWith("download/") }, "no key fetches; saw ${net.requests}")
        assertEquals(listOf("pgp-keys", "keystore"), net.uploads.map { it.kind })
        net.uploads.forEach { upload ->
            assertContentEquals(
                if (upload.kind == "pgp-keys") "pgp bundle".encodeToByteArray() else "keystore bundle".encodeToByteArray(),
                EnvelopeCodec.decryptSignedHybrid(upload.bytes, peerHybrid.privateKey, senderSignerKey),
            )
        }
    }

    // ------------------------------------------------------------------ fixtures: devices and keys

    private fun signedSenderDevice(): TrustedDevice = TrustedDevice(
        name = "upgraded peer",
        fingerprint = SENDER_FINGERPRINT,
        lastHost = "192.0.2.7",
        hybridPublicKey = Base64.Default.encode(serializedHybrid(peerHybrid)),
        mldsaPublicKey = Base64.Default.encode(peerMlDsa.publicKey),
        pairingSecurity = PairingSecurity.SignedHybridRequired,
    )

    private fun legacySenderDevice(): TrustedDevice = TrustedDevice(
        name = "legacy peer",
        fingerprint = SENDER_FINGERPRINT,
        lastHost = "192.0.2.7",
        pairingSecurity = PairingSecurity.LegacyRsa,
    )

    /** The peer the live loopback server impersonates, keyed to its real TLS identity. */
    private fun peerServerDevice(security: PairingSecurity): TrustedDevice = TrustedDevice(
        name = "peer server",
        fingerprint = fingerprintOf(peerRsa.public.encoded),
        lastHost = HOST,
        hybridPublicKey = Base64.Default.encode(serializedHybrid(peerHybrid)),
        mldsaPublicKey = Base64.Default.encode(peerMlDsa.publicKey),
        pairingSecurity = security,
    )

    private fun serializedHybrid(pair: HybridKem.KeyPair): ByteArray =
        EnvelopeCodec.serializePublicKey(pair.publicKey)

    private suspend fun localHybridPublicKey(): HybridKem.HybridPublicKey = localHybridPair().publicKey

    private suspend fun localHybridPrivate(): HybridKem.HybridPrivateKey = localHybridPair().privateKey

    /** This device's own hybrid pair, as the key manager persists/loads it for this test root. */
    private suspend fun localHybridPair(): HybridKem.KeyPair =
        assertNotNull(hybridManager(FakeTrustedDevices()).getKeyPair())

    private fun storedVault(): ByteArray =
        vaultCipher.decryptVault(storage.read(USER), sessionKey) { null }.plaintext

    private fun assertNothingStaged() {
        assertTrue(
            File(root, "database/tmp").listFiles().isNullOrEmpty(),
            "a rejected payload must never be staged",
        )
        assertTrue(!storage.exists(USER) || storage.read(USER).isEmpty(), "and never imported")
    }

    // ------------------------------------------------------------------ construction

    private fun hybridManager(devices: TrustedDevicesRepository) =
        HybridKeyManager(platform, JvmCryptoService(), preferences, devices)

    private fun mlDsaManager(devices: TrustedDevicesRepository) =
        MlDsaKeyManager(platform, JvmCryptoService(), preferences, devices)

    private fun passwordTransferService(devices: FakeTrustedDevices) = JvmPasswordTransferService(
        syncClient(SyncTlsProvider(preferences, devices), hybridManager(devices), mlDsaManager(devices)),
    )

    /** Everything the real storage does, except the one write the peer is waiting on. */
    private class FailingWriteStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        override fun write(username: String, encryptedBytes: ByteArray): Unit =
            throw IOException("simulated vault write failure")
    }

    private fun syncClient(
        syncTls: SyncTlsProvider,
        hybrid: HybridKeyManager,
        mldsa: MlDsaKeyManager,
    ) = ArtifactSyncClient(syncTls, hybrid, mldsa)

    private fun repository(
        devices: TrustedDevicesRepository,
        transferEvents: TransferEventPersistence = NoopTransferEvents,
        passwordStorage: PasswordDatabaseStorage = storage,
    ) = FileTransferRepository(
        platform = platform,
        coroutineScopeFacade = ImmediateScopeFacade(),
        coroutinesContextFacade = UnconfinedContexts,
        transferEventPersistence = transferEvents,
        passwordEventPersistence = NoopPasswordEvents,
        passwordDatabaseStorage = passwordStorage,
        pgpEventPersistence = NoopPgpEvents,
        keystoreEventPersistence = NoopKeystoreEvents,
        userPreferences = preferences,
        ipAddressProvider = NoIpAddress,
        syncTlsProvider = SyncTlsProvider(preferences, devices),
        hybridKeyManager = hybridManager(devices),
        mlDsaKeyManager = mlDsaManager(devices),
        vaultCipher = vaultCipher,
        entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
        qrPairingSession = unarmedQrPairingSession(),
    )

    private fun trustedDevices(): LocalTrustedDevicesRepository = LocalTrustedDevicesRepository(
        encryptedFactory = object : EncryptionSettingsFactory {
            override fun createEncrypted(name: String) = MapSettings()
        },
        userPreferences = preferences,
        userEvents = InMemoryUserEventsPersistence(UnconfinedContexts),
        coroutinesContextFacade = UnconfinedContexts,
    )

    // ------------------------------------------------------------------ live peer server

    private data class Upload(val bytes: ByteArray, val name: String, val pin: String?, val kind: String)

    private inner class PeerServer(
        val port: Int,
        val requests: CopyOnWriteArrayList<String>,
        val uploads: CopyOnWriteArrayList<Upload>,
    )

    /**
     * A real k2k mTLS server on the loopback, presenting the peer's RSA identity and pinning this
     * test's sender identity — the same TLS geometry as two paired passman devices. It records
     * every download request and upload so the tests can observe *absence* of wire key fetches.
     */
    private fun startPeerServer(
        servedHybridKey: ByteArray = ByteArray(0),
        servedMlDsaKey: ByteArray = ByteArray(0),
        pullResponse: ((wireClientKey: ByteArray) -> ByteArray)? = null,
    ): PeerServer {
        val port = ServerSocket(0).use { it.localPort }
        val requests = CopyOnWriteArrayList<String>()
        val uploads = CopyOnWriteArrayList<Upload>()
        val password = "peer-server".toCharArray()
        val keyStore = TlsIdentity.buildSessionKeyStore(peerRsa.private, peerRsa.public, password)
        server = startServer(
            port = port,
            tempFilePath = File(root, "peer-server-tmp").apply { mkdirs() }.absolutePath,
            getFileFromName = { name ->
                requests.add("download/$name")
                when (name) {
                    "hybridPublicKey" -> servedHybridKey
                    "mldsaPublicKey" -> servedMlDsaKey
                    else -> ByteArray(0)
                }
            },
            onFileUploaded = { bytes, name, pin -> uploads.add(Upload(bytes, name, pin, "passwords")) },
            artifactUploadHandlers = mapOf(
                "pgp-keys" to { bytes, name, pin -> uploads.add(Upload(bytes, name, pin, "pgp-keys")) },
                "keystore" to { bytes, name, pin -> uploads.add(Upload(bytes, name, pin, "keystore")) },
            ),
            syncPullHandlers = mapOf(
                "passwords" to { wireKey, _ ->
                    requests.add("sync-pull/passwords")
                    pullResponse?.invoke(wireKey)
                },
            ),
            serverTls = K2kServerTls(keyStore, password, TlsIdentity.ALIAS, setOf(SENDER_TLS_PIN)),
        ).also { it.start(wait = false) }
        awaitListening(port)
        return PeerServer(port, requests, uploads)
    }

    private fun awaitListening(port: Int) {
        repeat(100) {
            try {
                Socket("127.0.0.1", port).close()
                return
            } catch (_: Exception) {
                Thread.sleep(50)
            }
        }
        error("peer server did not start")
    }

    // ------------------------------------------------------------------ fakes

    /** Recording repository: [writes] counts every mutation, so "not promoted" is observable. */
    private class FakeTrustedDevices(vararg initial: TrustedDevice) : TrustedDevicesRepository {
        private val devices = initial.toMutableList()
        var writes = 0
            private set

        override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
        override suspend fun getAll(): List<TrustedDevice> = devices.toList()
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean {
            writes++
            devices.removeAll { it.name == device.name }
            devices += device
            return true
        }

        override suspend fun remove(name: String) {
            writes++
            devices.removeAll { it.name == name }
        }

        override suspend fun getByHost(host: String): TrustedDevice? = devices.firstOrNull { it.lastHost == host }
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) {
            writes++
        }

        override suspend fun updateHost(name: String, host: String) {
            writes++
        }

        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) {
            writes++
        }

        override suspend fun markSignedHybridPairingsForReverification() {
            writes++
        }
    }

    private class TestPreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn(USER, Password("hash", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "signed-hybrid-sync-policy"
        override suspend fun clear() = Unit
    }

    private class ImmediateScopeFacade : CoroutineScopeFacade {
        override val globalScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
        override var transferScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())
    }

    private object UnconfinedContexts : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }

    private object NoopTransferEvents : TransferEventPersistence {
        override fun events(): Flow<TransferEvent> = emptyFlow()
        override suspend fun update(event: TransferEvent) = Unit
    }

    private class RecordingTransferEvents : TransferEventPersistence {
        val recorded = mutableListOf<TransferEvent>()
        override fun events(): Flow<TransferEvent> = emptyFlow()
        override suspend fun update(event: TransferEvent) {
            recorded += event
        }
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

    private object NoIpAddress : IpAddressProvider {
        override suspend fun getLocalIpAddress(): String = HOST
    }

    private companion object {
        const val USER = "alice"
        const val HOST = "127.0.0.1"
        const val STAGED = "staged-db"

        /** Frozen RSA SPKI fingerprint of the simulated sender; pin form is its lowercase no-colon twin. */
        const val SENDER_FINGERPRINT = "AA:BB:CC:DD"
        const val SENDER_PIN = "aabbccdd"

        // Shared immutable fixtures — generated once; every test only reads them.
        val localRsa: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val peerRsa: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val peerHybrid: HybridKem.KeyPair = HybridKem.generateKeyPair()
        val peerMlDsa: MlDsa.KeyPair = MlDsa.generateKeyPair()

        /** SPKI pin of the local (sender) TLS identity, as the peer server must store it. */
        val SENDER_TLS_PIN: String = MessageDigest.getInstance("SHA-256")
            .digest(localRsa.public.encoded)
            .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

        fun fingerprintOf(publicKeyBytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(publicKeyBytes)
            .joinToString(":") { "%02X".format(it.toInt() and 0xFF) }
    }
}
