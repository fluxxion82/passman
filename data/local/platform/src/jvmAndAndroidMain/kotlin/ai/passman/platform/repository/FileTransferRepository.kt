package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.vault.PortableVaultFormat
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.QrPairingSession
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.domain.settings.repository.TransferRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import com.k2k.test.server.startServer
import com.k2k.test.server.PairingBundleExchange
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.core.qualifier.named
import org.koin.mp.KoinPlatform
import java.io.File
import java.security.Key

/**
 * Shared receive-side server + reconcile logic for desktop and android.
 * Local-IP lookup is delegated to a platform service because it requires platform APIs
 * (NetworkInterface on desktop, WifiManager on android).
 *
 * ## Wire format and at-rest format are separate decisions
 *
 * What arrives on the wire may be classical (v2), hybrid (v3) or signed hybrid (v4) — which of
 * those the *sender's pairing* permits is decided per authenticated caller in
 * [InboundSyncPolicy.decryptInbound], keyed on the SPKI pin the k2k server threads through to every
 * upload and sync-pull handler.
 * What is *stored* afterwards is always a suite-5 vault sealed under this device's own session key. Re-sealing an inbound payload under RSA, which is
 * what this used to do, silently dragged a migrated account back onto the wrapping the vault
 * migration exists to remove: one sync and the vault was RSA-wrapped again, with a
 * `.premigration.v2` artifact beside it describing a state the vault had returned to.
 *
 * Staged files written by an older build are still read through the legacy path, because the update
 * may find one already sitting in `database/tmp`.
 */
class FileTransferRepository(
    private val platform: Platform,
    private val coroutineScopeFacade: CoroutineScopeFacade,
    private val coroutinesContextFacade: CoroutinesContextFacade,
    private val transferEventPersistence: TransferEventPersistence,
    private val passwordEventPersistence: PasswordEventPersistence,
    private val passwordDatabaseStorage: PasswordDatabaseStorage,
    private val pgpEventPersistence: PgpEventPersistence,
    private val keystoreEventPersistence: KeystoreEventPersistence,
    private val userPreferences: UserPreferences,
    private val ipAddressProvider: IpAddressProvider,
    private val syncTlsProvider: SyncTlsProvider,
    private val hybridKeyManager: HybridKeyManager,
    private val mlDsaKeyManager: MlDsaKeyManager,
    private val vaultCipher: VaultCipher,
    private val entryIdentity: PasswordEntryIdentity,
    private val qrPairingSession: QrPairingSession,
    private val portableVaultFormat: PortableVaultFormat? = null,
) : TransferRepository {
    private val tmpDir = "${platform.getLocalPath()}/database/tmp"
    private var embeddedServer: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null
    private var pairingServer: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>? = null

    // The data server is shared: three independent artifact sync sessions (passwords, PGP,
    // keystore) can each be mid-window at once, and each takes out a lease via
    // startTransferServer(). It is refcounted rather than boolean so the caller that finishes
    // first cannot tear the server out from under a sibling session still using it —
    // stopTransferServer only actually stops the server once the last lease is released. A plain
    // var, not an AtomicBoolean/AtomicInteger: everything that touches it now runs inline under
    // transferServerLock instead of racing a launched coroutine, so there is nothing left for
    // atomicity to buy, and a second, separately-synchronized flag would just be one more place
    // for "running" to say something the lease count disagrees with.
    private var transferServerLeases = 0

    // Start and stop serialise under this lock, mirroring pairingServerLock below: a start
    // arriving mid-stop must wait for the teardown to actually finish (or discover it never
    // touched the server, because another lease is still held) rather than observe a
    // half-torn-down server, and two concurrent starts must not both decide they are "the first"
    // and bind the port twice.
    private val transferServerLock = Mutex()

    // The pairing listener instead starts and stops inline under this lock. Its callers sequence
    // stop-then-start restarts around every ceremony and rely on teardown really tearing down,
    // which only works when start has finished (or failed) by the time it returns.
    private val pairingServerLock = Mutex()

    private val _peerHandshakeComplete = MutableStateFlow(false)
    override val peerHandshakeComplete: StateFlow<Boolean> = _peerHandshakeComplete
    private var inboundPushes = 0
    private var inboundSyncPulls = 0

    // The two collaborators this class delegates to are built here rather than injected: they are an
    // internal decomposition, not a DI seam, so the constructor above stays the one every caller and
    // every test already writes. The session-scope lookups stay on this side and cross as lambdas.
    private val inboundSyncPolicy = InboundSyncPolicy(
        syncTlsProvider = syncTlsProvider,
        hybridKeyManager = hybridKeyManager,
        mlDsaKeyManager = mlDsaKeyManager,
        legacyPrivateKey = { sessionScope().get<Key>(named(PRIVATE_DECRYPTION_KEY)) },
    )

    private val vaultReconciler = VaultReconciler(
        passwordDatabaseStorage = passwordDatabaseStorage,
        userPreferences = userPreferences,
        vaultCipher = vaultCipher,
        entryIdentity = entryIdentity,
        tmpDir = tmpDir,
        sessionKey = { sessionKey() },
        legacyKeyHandle = { legacyKeyHandle() },
        portableVaultFormat = portableVaultFormat,
    )

    init {
        File(tmpDir).mkdirs()
    }

    @Synchronized
    private fun recordInboundPush() {
        inboundPushes++
        if (inboundPushes > 0 && inboundSyncPulls > 0) _peerHandshakeComplete.value = true
    }

    @Synchronized
    private fun recordInboundSyncPull() {
        inboundSyncPulls++
        if (inboundPushes > 0 && inboundSyncPulls > 0) _peerHandshakeComplete.value = true
    }

    override suspend fun getIpAddress(): String = ipAddressProvider.getLocalIpAddress()

    /**
     * Starts the shared TLS data server that all three artifact sync sessions (passwords, PGP,
     * keystore) sync through, or joins an already-running one.
     *
     * Refcounted, like [startPairingServer]/[stopPairingServer]: this call takes out one lease on
     * the server and [stopTransferServer] releases one, and the server itself only actually stops
     * once the last lease is released. Three independent Home ViewModels can each have a sync
     * session mid-window at once; without this, whichever session finished first tore the server
     * out from under a sibling session still using it — up to a 60s window, and the best candidate
     * for a real report of intermittent sync failures that succeeded on retry.
     *
     * Runs the actual bind inline, under [transferServerLock], exactly as [startPairingServer]
     * does — so by the time this suspend function returns, the socket is either accepting
     * connections or this call has thrown. (In the pinned Ktor 3.5.2,
     * `NettyApplicationEngine.start(wait = false)` binds synchronously and throws on a failed
     * bind, which is the entire mechanism this relies on; there is deliberately no wait on
     * `resolvedConnectors()` here, since that handle only completes on a *successful* bind and
     * would hang forever on exactly the `BindException` this needs to surface.) A concurrent
     * caller blocked on the same lock therefore never observes a half-bound server: it either
     * finds one already accepting, or it acquires the lock after a failed attempt has rolled
     * itself back and makes its own attempt.
     *
     * A bind failure is rethrown, not swallowed. Turning that into a user-visible session error is
     * the caller's job — this only guarantees the failure is no longer invisible.
     */
    override suspend fun startTransferServer() {
        withContext(coroutinesContextFacade.default) {
            transferServerLock.withLock {
                transferServerLeases++
                if (embeddedServer != null) {
                    KLogger.d { "startTransferServer: already running, lease=$transferServerLeases" }
                    return@withLock
                }
                // Reset handshake state for a fresh session.
                inboundPushes = 0
                inboundSyncPulls = 0
                _peerHandshakeComplete.value = false

                coroutineScopeFacade.transferScope.cancel()
                coroutineScopeFacade.transferScope =
                    CoroutineScope(coroutinesContextFacade.default + SupervisorJob())
                runCatching {
                    // Mutual-TLS material for the data port: presents this device's cert and only
                    // admits clients whose SPKI pins to a paired device (ClientAuth.REQUIRE). Built
                    // before starting so the server never comes up plaintext once the user is signed
                    // in with paired devices.
                    //
                    // Inside the runCatching, not before it: this resolves the session scope through
                    // Koin and can throw, and a throw out here would leave the lease taken out above
                    // held with no server to match it — the exact invariant the rollback below
                    // exists to keep.
                    val serverTls = syncTlsProvider.serverTls()
                    KLogger.i { "start server (mTLS=${serverTls != null})" }
                    embeddedServer = startServer(
                        port = DATA_PORT,
                        tempFilePath = tmpDir,
                        getFileFromName = ::processFileRequest,
                        onFileUploaded = ::processUploadedFile,
                        artifactUploadHandlers = mapOf(
                            "pgp-keys" to ::processPgpKeysUploaded,
                            "keystore" to ::processKeystoreUploaded,
                        ),
                        syncPullHandlers = mapOf(
                            "passwords" to ::providePasswordSyncPull,
                            "pgp-keys" to ::providePgpSyncPull,
                            "keystore" to ::provideKeystoreSyncPull,
                        ),
                        serverTls = serverTls,
                        // Narrow each paired device to only its permitted ops (esp. gate pgp-import).
                        authorizer = syncTlsProvider::authorize,
                    )
                    embeddedServer?.start()
                }.onFailure {
                    // Roll back so a later start is not permanently wedged behind this attempt's
                    // failure: the lease taken out above must not outlive the server it failed to
                    // produce, or the next call's "already running" check above would lie.
                    embeddedServer = null
                    transferServerLeases--
                    if (it is CancellationException) throw it
                    KLogger.e(it) { "transfer server failed to start" }
                }.getOrThrow()
            }
        }
    }

    /**
     * Plaintext listener used ONLY during the explicit pairing ceremony. It retains the legacy RSA
     * public-key fetch and adds the bounded identity-bundle exchange; its k2k pairing mode does not
     * register any vault, PGP, keystore, upload, or sync-pull route. It runs on a separate port
     * from the TLS-only data server and only while the Trusted Devices screen is visible.
     *
     * Unlike the transfer server this starts inline, not in a launched coroutine: the Trusted
     * Devices screen restarts the listener with stop-then-start around every ceremony and its
     * teardown must be able to trust that a returned stop left nothing behind. A fire-and-forget
     * start can interleave with a subsequent stop and leak a plaintext listener no caller can
     * ever reach again.
     */
    override suspend fun startPairingServer() {
        withContext(coroutinesContextFacade.default) {
            pairingServerLock.withLock {
                if (pairingServer != null) {
                    KLogger.d { "startPairingServer: already running, no-op" }
                    return@withLock
                }
                runCatching {
                    KLogger.i { "start pairing server (plaintext, public identity exchange only)" }
                    pairingServer = startServer(
                        port = PAIRING_PORT,
                        tempFilePath = tmpDir,
                        getFileFromName = ::processPairingFileRequest,
                        // Three-arg on purpose: the plaintext pairing listener has no verified caller
                        // pin by design, and it never accepts uploads regardless.
                        onFileUploaded = { _, _, _ -> /* pairing server never accepts uploads */ },
                        pairingBundleExchange = PairingBundleExchange(
                            localBundle = { Json.encodeToString(localDeviceIdentityBundle()).encodeToByteArray() },
                            validatePeerBundle = ::isValidPairingBundle,
                            // A received bundle is still never retained here; QrPairingSession only
                            // arms PendingPairing when a QR nonce is registered and the possession
                            // proof verifies. Its verdict decides whether the listener's
                            // single-accept slot burns.
                            onPeerBundle = { bundle, proof, remoteHost ->
                                qrPairingSession.onInboundBundle(bundle, proof, remoteHost)
                            },
                        ),
                    )
                    pairingServer?.start()
                }.onFailure {
                    KLogger.e(it) { "pairing server failed to start" }
                    pairingServer = null
                }
            }
        }
    }

    override suspend fun stopPairingServer() {
        withContext(coroutinesContextFacade.default) {
            pairingServerLock.withLock {
                KLogger.d { "stopPairingServer" }
                pairingServer?.stop(gracePeriodMillis = 500, timeoutMillis = 2_000)
                pairingServer = null
            }
        }
    }

    private suspend fun processPairingFileRequest(fileName: String): ByteArray = when (fileName) {
        "publicKey" -> processFileRequest("publicKey")
        else -> byteArrayOf()
    }

    private suspend fun localDeviceIdentityBundle(): DeviceIdentityBundle {
        val sessionScope = sessionScope()
        val rsaPublicKey: Key = sessionScope.get(named(PUBLIC_ENCRYPTION_KEY))
        val hybridPublicKey = hybridKeyManager.getPublicKeySerialized()
            ?: error("hybrid public key unavailable for pairing")
        val mldsaPublicKey = mlDsaKeyManager.getPublicKeySerialized()
            ?: error("ML-DSA public key unavailable for pairing")
        return DeviceIdentityBundle.local(
            rsaSpki = rsaPublicKey.encoded,
            hybridPublicKey = hybridPublicKey,
            mldsaPublicKey = mldsaPublicKey,
        )
    }

    private fun isValidPairingBundle(bytes: ByteArray): Boolean = runCatching {
        Json.decodeFromString<DeviceIdentityBundle>(bytes.decodeToString())
    }.isSuccess

    /**
     * Releases one lease taken out by [startTransferServer]. The server itself only stops once the
     * last lease is released — see [startTransferServer]'s doc for why it is refcounted at all.
     *
     * Runs off Main, under [transferServerLock], and (like [startTransferServer]) serialises with
     * every other start/stop: a start arriving mid-teardown here waits for this call to finish —
     * either because the socket really came down and the start rebinds, or because another lease
     * was still held and this call never touched the server at all.
     */
    override suspend fun stopTransferServer() {
        // NonCancellable is load-bearing, not defensive. The only production caller is
        // runSyncSession's `onCompletion`, which runs in the collector *after* it has been
        // cancelled — every user cancel, every cancelAndJoin restart, every VM clear mid-sync.
        // A plain withContext calls ensureActive() first and throws without running its block
        // there, so teardown would silently never happen: the lease would never be released, the
        // mTLS server would hold port 2323 for the rest of the process, and a stale
        // _peerHandshakeComplete would make later sessions' Phase B release instantly. The old
        // blocking stop() had no suspension point and so was immune; making this suspend is what
        // introduced the hazard. `recordingOutcomes` in SyncPasswords.kt guards its own
        // onCompletion writes the same way, for the same reason.
        withContext(NonCancellable + coroutinesContextFacade.default) {
            transferServerLock.withLock {
                if (transferServerLeases > 0) {
                    transferServerLeases--
                } else {
                    // A stop with no lease outstanding means some caller's start/stop pairing is
                    // broken. Absorbed rather than thrown — a teardown path is the wrong place to
                    // start failing — but never silently, because the next symptom is a sibling
                    // session losing its server to a stop it did not own.
                    KLogger.w { "stopTransferServer: no lease outstanding - unpaired stop" }
                }
                KLogger.d { "stopTransferServer: lease=$transferServerLeases" }
                if (transferServerLeases > 0) {
                    // Another session's window still depends on this server. Stopping here is
                    // exactly the reported bug: an unrefcounted stop let one artifact's session
                    // finishing first kill the socket out from under a sibling session's still-open
                    // window.
                    return@withLock
                }
                // Grace period so an in-flight sync-pull response finishes flushing before the
                // socket closes. Without it, the moment the last lease's handshake completed it
                // tore the server down mid-response and the peer's pull failed with
                // EOFException ("server prematurely closed").
                //
                // stopSuspend, not the blocking stop(): this is called from `onCompletion` on Main,
                // and the blocking call held Main for the whole 1.5-4s grace/timeout window on
                // every session end. stopSuspend (added in this Ktor version) does the identical
                // wait off-thread instead.
                embeddedServer?.stopSuspend(gracePeriodMillis = 1_500, timeoutMillis = 4_000)
                embeddedServer = null
            }
        }
    }

    override suspend fun isTransferServerRunning(): Boolean = embeddedServer != null

    private suspend fun processFileRequest(fileName: String): ByteArray = when (fileName) {
        "publicKey" -> {
            KLogger.d { "return public key" }
            val sessionScope = sessionScope()
            val key: Key = sessionScope.get(named(PUBLIC_ENCRYPTION_KEY))
            key.encoded
        }
        "hybridPublicKey" -> {
            // Post-quantum recipient key, served over the mTLS-authenticated data server so a paired
            // peer can encrypt suite-v3 payloads to this device.
            hybridKeyManager.getPublicKeySerialized() ?: byteArrayOf()
        }
        "mldsaPublicKey" -> mlDsaKeyManager.getPublicKeySerialized() ?: byteArrayOf()
        else -> byteArrayOf()
    }

    internal suspend fun processUploadedFile(fileBytes: ByteArray, fileName: String, senderPin: String?) {
        kotlin.runCatching {
            KLogger.d { "processUploadedFile, $fileName, size: ${fileBytes.size}" }
            // Resolve WHO sent this before any decrypt or staging, then decrypt under that device's
            // pairing policy. What is accepted on the wire (legacy v2/v3 vs. strict signed v4) is a
            // property of the sender's pairing, not of the payload's own claims. The decrypted
            // payload is then sealed to the *local* at-rest format — suite 5, under this device's
            // session key. The staged copy under the logical name is what executeReconcileAction
            // consumes on conflict, and on the no-conflict path below it is copied straight in as
            // the vault, so it has to be in exactly the format a vault read expects.
            val plaintext = inboundSyncPolicy.decryptInbound(inboundSyncPolicy.trustedSender(senderPin), fileBytes)
            val tmpFile = File(tmpDir, fileName)
            tmpFile.writeBytes(vaultCipher.encryptVault(plaintext, sessionKey()))
            val user = userPreferences.getUser() as AppUser.LoggedIn

            // Inline, NOT launched. k2k answers the peer 200 the moment this function returns
            // normally and 500 if it throws, so anything the peer is being told succeeded has to
            // have happened by then. With the write inside a launched coroutine the peer was told
            // its vault had landed while the write was still pending — and if it then failed, the
            // peer had already recorded a successful sync and would not send again.
            //
            // Through the storage interface, not a raw copy onto the vault path. The raw copy
            // bypassed the write monitor, the cross-process lock, the atomic publish, the `.bak`
            // generation and `SecureFiles.ownerOnly` — it was the one writer that falsified
            // "every writer goes through this object", on the file whose loss is the worst
            // outcome the product has.
            val conflict = passwordDatabaseStorage.exists(user.userName) &&
                passwordDatabaseStorage.read(user.userName).isNotEmpty()

            if (!conflict) {
                passwordDatabaseStorage.write(user.userName, tmpFile.readBytes())
                tmpFile.delete()
                KLogger.d { "processUploadedFile, auto-imported into the vault for ${user.userName}" }
            }

            // Notifications stay launched, and deliberately so: these are MutableSharedFlows with a
            // small buffer that SUSPEND on overflow, so emitting inline would let a slow collector
            // on the UI hold the peer's HTTP response open. A dropped notification costs a screen
            // refresh; a dropped write costs the vault.
            KLogger.d { "processUploadedFile, transfer event conflict=$conflict" }
            coroutineScopeFacade.transferScope.launch {
                if (!conflict) passwordEventPersistence.update(PasswordEvent.Updated)
                transferEventPersistence.update(TransferEvent.PassFileReceived(conflict = conflict))
            }
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to process upload file" }
        }.getOrThrow()
        recordInboundPush()
    }

    internal suspend fun processPgpKeysUploaded(fileBytes: ByteArray, fileName: String, senderPin: String?) {
        kotlin.runCatching {
            KLogger.d { "processPgpKeysUploaded, $fileName, size: ${fileBytes.size}" }
            val decryptedBundle = inboundSyncPolicy.decryptInbound(inboundSyncPolicy.trustedSender(senderPin), fileBytes)
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val destDir = File("${platform.getLocalPath()}/pgp/${user.userName}")
            DirectoryBundler.unbundle(decryptedBundle, destDir)

            coroutineScopeFacade.transferScope.launch {
                pgpEventPersistence.update(PgpEvent.KeyModified)
                transferEventPersistence.update(TransferEvent.PgpKeysReceived)
            }
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to process pgp keys upload" }
        }.getOrThrow()
        recordInboundPush()
    }

    internal suspend fun processKeystoreUploaded(fileBytes: ByteArray, fileName: String, senderPin: String?) {
        kotlin.runCatching {
            KLogger.d { "processKeystoreUploaded, $fileName, size: ${fileBytes.size}" }
            val decryptedBundle = inboundSyncPolicy.decryptInbound(inboundSyncPolicy.trustedSender(senderPin), fileBytes)
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val destDir = File("${platform.getLocalPath()}/keystore/${user.userName}")
            // Never let an inbound keystore push replace the device's primary login keystore.
            val excluded = DirectoryBundler.syncExclusions(user.userName)
            DirectoryBundler.unbundle(decryptedBundle, destDir, excludeBaseNames = excluded)

            coroutineScopeFacade.transferScope.launch {
                keystoreEventPersistence.update(KeystoreEvent.Updated)
                transferEventPersistence.update(TransferEvent.KeystoreReceived)
            }
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to process keystore upload" }
        }.getOrThrow()
        recordInboundPush()
    }

    internal suspend fun providePasswordSyncPull(clientPublicKeyBytes: ByteArray, callerPin: String?): ByteArray? {
        val result = runCatching {
            val caller = inboundSyncPolicy.trustedSender(callerPin)
            val user = userPreferences.getUser() as AppUser.LoggedIn
            if (!passwordDatabaseStorage.exists(user.userName)) return@runCatching null
            val stored = passwordDatabaseStorage.read(user.userName)
            if (stored.isEmpty()) return@runCatching null

            val decrypted = vaultReconciler.openVault(stored)
            inboundSyncPolicy.sealSyncPullResponse(caller, decrypted, clientPublicKeyBytes)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "providePasswordSyncPull failed" }
        }.getOrThrow()
        // Record the completed handshake only after the response is built, so the resulting
        // server teardown (Phase B releasing) cannot race the response we still need to send.
        recordInboundSyncPull()
        return result
    }

    internal suspend fun providePgpSyncPull(clientPublicKeyBytes: ByteArray, callerPin: String?): ByteArray? {
        val result = runCatching {
            val caller = inboundSyncPolicy.trustedSender(callerPin)
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val pgpDir = File("${platform.getLocalPath()}/pgp/${user.userName}")
            if (!pgpDir.isDirectory || pgpDir.listFiles()?.isEmpty() != false) return@runCatching null

            val bundle = DirectoryBundler.bundle(pgpDir)
            inboundSyncPolicy.sealSyncPullResponse(caller, bundle, clientPublicKeyBytes)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "providePgpSyncPull failed" }
        }.getOrThrow()
        recordInboundSyncPull()
        return result
    }

    internal suspend fun provideKeystoreSyncPull(clientPublicKeyBytes: ByteArray, callerPin: String?): ByteArray? {
        val result = runCatching {
            val caller = inboundSyncPolicy.trustedSender(callerPin)
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val keystoreDir = File("${platform.getLocalPath()}/keystore/${user.userName}")
            if (!keystoreDir.isDirectory || keystoreDir.listFiles()?.isEmpty() != false) return@runCatching null

            // Don't ship the user's primary login keystore to the peer.
            val excluded = DirectoryBundler.syncExclusions(user.userName)
            val bundle = DirectoryBundler.bundle(keystoreDir, excludeBaseNames = excluded)
            inboundSyncPolicy.sealSyncPullResponse(caller, bundle, clientPublicKeyBytes)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "provideKeystoreSyncPull failed" }
        }.getOrThrow()
        recordInboundSyncPull()
        return result
    }

    override suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit> =
        vaultReconciler.executeReconcileAction(reconcileAction)

    private suspend fun sessionScope() = KoinPlatform.getKoin().getOrCreateScope(
        "session-${userPreferences.getSessionId()}",
        named("sessionScope"),
    )

    /**
     * The unwrapped device master key for this session.
     *
     * Fails loudly when nothing is bound rather than degrading: every caller here is about to either
     * write the vault or serve it to a peer, and doing that without a session key is not a milder
     * outcome than an exception.
     */
    private suspend fun sessionKey(): VaultSessionKey =
        sessionScope().get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()

    /**
     * The lazy legacy-RSA lookup `VaultCipher.decryptVault` consults for pre-suite-5 bytes, resolved
     * against this session's scope.
     *
     * Two stages because that provider is not a suspending function: the scope is resolved here,
     * suspending, and the key itself only if a legacy envelope actually turns up — so the ordinary
     * path never opens the PKCS#12 identity store. `runCatching` because the definition takes two
     * parameters and fails rather than returning null on a scope login never warmed; either way the
     * answer is "no legacy key", which `decryptVault` reports as a typed failure instead of a crash.
     */
    private suspend fun legacyKeyHandle(): () -> CryptoKey? {
        val scope = sessionScope()
        return { runCatching { scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) }.getOrNull() }
    }

    internal companion object {
        /**
         * The TLS data server's port. Internal rather than private so the readiness tests that dial
         * this port read the port it actually opens — a copy of the literal in a test is a copy
         * that goes on passing after this one moves.
         */
        internal const val DATA_PORT = 2323

        /**
         * The plaintext pairing listener's port. Internal rather than private so the tests that
         * dial this listener read the port it actually opens — a copy of the literal in a test is a
         * copy that goes on passing after this one moves.
         *
         * Aliased to the domain constant rather than repeating the number: a QR advertises
         * [PairingQrPayload.DEFAULT_PAIRING_PORT] while this is the port that actually gets bound,
         * so two independent literals agreeing was luck, and moving one would have pointed every
         * pairing code at a closed port with nothing failing at compile time.
         */
        const val PAIRING_PORT = PairingQrPayload.DEFAULT_PAIRING_PORT
    }
}
