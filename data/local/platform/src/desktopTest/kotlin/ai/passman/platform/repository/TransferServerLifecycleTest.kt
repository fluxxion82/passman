package ai.passman.platform.repository

import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.repository.FileTransferRepository.Companion.DATA_PORT
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module

/**
 * The data server's refcounted start/stop contract, shared by the three independent artifact sync
 * sessions (passwords, PGP, keystore):
 *
 * - when `startTransferServer()` returns, the socket is actually accepting connections, or the
 *   call has thrown — never anything in between;
 * - the server only actually stops once every caller that took out a lease has released it via
 *   `stopTransferServer()`, so the session that finishes first can never tear the server out from
 *   under a sibling session whose window is still open. That is the reported bug this whole fix
 *   exists for (see obligation 13 below).
 *
 * The transfer scope in this fixture deliberately never executes anything it is handed, exactly as
 * `PairingServerLifecycleTest` does for the pairing listener: if the data server ever goes back to
 * starting inside a launched coroutine, every real-socket assertion below fails outright — on a
 * `ConnectException`, not on timing — instead of quietly passing.
 */
class TransferServerLifecycleTest {

    private lateinit var root: File
    private lateinit var repository: FileTransferRepository

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("transfer-server-lifecycle").toFile()
        // The data server's start path asks SyncTlsProvider for server TLS, and that resolves the
        // session scope through Koin — which throws outright when no Koin application is running,
        // rather than answering "no session". The scope is declared here and left EMPTY on purpose:
        // with no identity keys in it, sessionKeyStore() returns null, serverTls() returns null, and
        // the server binds plaintext. That is exactly right for a raw-socket readiness probe, which
        // asks only "is the port accepting", and it keeps the fixture from depending on TLS material
        // none of these assertions are about. (PairingServerLifecycleTest needs none of this: the
        // pairing listener is plaintext by design and never calls serverTls().)
        startKoin {
            modules(module { scope(named("sessionScope")) { } })
        }
        val platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        val preferences = FakePreferences()
        val devices = FakeTrustedDevices()
        val crypto = JvmCryptoService()
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
            hybridKeyManager = HybridKeyManager(platform, crypto, preferences, devices),
            mlDsaKeyManager = MlDsaKeyManager(platform, crypto, preferences, devices),
            vaultCipher = PasswordVaultCipher(crypto),
            entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
            qrPairingSession = unarmedQrPairingSession(),
        )
    }

    @AfterTest
    fun tearDown() {
        runBlocking {
            // Release generously: a test that stops early on a failed assertion may still be
            // holding one or two leases. Releasing more than were taken is a harmless no-op —
            // stopTransferServer refuses to take the lease count negative and no-ops once
            // embeddedServer is already null.
            repeat(4) { repository.stopTransferServer() }
        }
        // Every test must hand the next one a genuinely free port. Without this the leak shows up
        // as a failure in whichever test runs next — and SO_REUSEADDR means the next start can
        // succeed *alongside* a server that never came down, so the symptom is a phantom extra
        // server rather than a clean bind failure.
        check(awaitPortFree()) { "a server outlived this test and still holds $DATA_PORT" }
        // Koin is global process state, so a leak here would follow the next test into its own run.
        stopKoin()
        root.deleteRecursively()
    }

    /** Obligation 10: startTransferServer() does not return until the socket accepts. */
    @Test
    fun startDoesNotReturnUntilTheSocketAcceptsAndStopReleasesThePort() = runBlocking {
        repository.startTransferServer()
        Socket("127.0.0.1", DATA_PORT).use { socket ->
            assertTrue(socket.isConnected, "server must accept connections once start returns")
        }

        repository.stopTransferServer()
        assertPortFree()
    }

    /**
     * Obligation 11: a concurrent second `startTransferServer()` waits for readiness rather than
     * returning early, including the branch where the first caller's bind fails — the second must
     * observe the failure itself and never report a false "ready".
     *
     * The port is occupied *before* either caller starts, so every real bind attempt below is
     * guaranteed to fail: this is what makes "neither call may report success" a fact this test can
     * actually pin, rather than a timing hope.
     */
    @Test
    fun concurrentStartDuringAFailedBindNeverReturnsAFalseReady() = runBlocking {
        // Wildcard, matching the server's own connector (k2k's `connector { this.port = port }`
        // defaults to 0.0.0.0) - not a loopback bind. `ServerSocket()` on this JDK/macOS has
        // SO_REUSEADDR on by default and nothing here turns it off, but that flag only relaxes
        // TIME_WAIT reuse and wildcard-vs-specific-address coexistence (e.g. 0.0.0.0:port next to
        // 127.0.0.1:port); it does not let two sockets both bind the *same* wildcard address:port
        // at once - that coexistence needs SO_REUSEPORT, which nothing here sets. So it is binding
        // the wildcard, not the state of SO_REUSEADDR, that actually guarantees every real bind
        // attempt below fails; a loopback-only blocker would not reliably occupy the port the
        // server itself binds to, and the "every bind here must fail" premise this test rests on
        // would silently stop holding.
        val blocker = ServerSocket()
        blocker.bind(InetSocketAddress(DATA_PORT))
        try {
            val first = async(Dispatchers.Default) { runCatching { repository.startTransferServer() } }
            val second = async(Dispatchers.Default) { runCatching { repository.startTransferServer() } }
            val results = awaitAll(first, second)
            assertTrue(
                results.all { it.isFailure },
                "both callers must observe the bind failure; neither may return normally while " +
                    "nothing is actually listening",
            )
        } finally {
            blocker.close()
        }

        // The failed attempts must not leave the lease count wedged: once the port is free, a
        // start still succeeds.
        repository.startTransferServer()
        Socket("127.0.0.1", DATA_PORT).use { socket ->
            assertTrue(socket.isConnected, "a start after the port frees up must still succeed")
        }
        repository.stopTransferServer()
        assertPortFree()
    }

    /** Obligation 12: a start arriving during an in-flight stop still yields a listening server. */
    @Test
    fun startArrivingDuringAnInFlightStopStillYieldsAListeningServer() = runBlocking {
        repository.startTransferServer()

        // Race a stop against a start with no delay between them. Serialised under
        // transferServerLock, so however the two interleave, the end state is well-defined: either
        // the start wins the lock first and rejoins the still-live server, or the stop wins first,
        // actually tears the server down, and the start (unblocked only once that finishes)
        // rebinds. Both outcomes leave a listening server; neither leaves the socket half-torn-down.
        val stopping = async(Dispatchers.Default) { repository.stopTransferServer() }
        val starting = async(Dispatchers.Default) { repository.startTransferServer() }
        awaitAll(stopping, starting)

        Socket("127.0.0.1", DATA_PORT).use { socket ->
            assertTrue(socket.isConnected, "a start racing an in-flight stop must still yield a listening server")
        }
    }

    /**
     * Obligation 13, the actual reported bug: two overlapping sync sessions share the server, and
     * the one that finishes first must not stop it out from under the one still running.
     */
    @Test
    fun theFirstOfTwoOverlappingSessionsToFinishDoesNotStopTheServerForTheSecond() = runBlocking {
        repository.startTransferServer() // session A's lease
        repository.startTransferServer() // session B's lease, joins A's already-running server

        repository.stopTransferServer() // A finishes first and releases its lease

        // B's window is still open. Its server must still be up — this is exactly what the
        // unrefcounted original implementation got wrong: A's stop tore the server down
        // unconditionally, regardless of B still holding it.
        Socket("127.0.0.1", DATA_PORT).use { socket ->
            assertTrue(
                socket.isConnected,
                "a sibling session's still-open lease must keep the server up after the first " +
                    "session's stop",
            )
        }

        repository.stopTransferServer() // B finishes and releases the last lease
        assertPortFree()
    }

    /**
     * The teardown path runs from `runSyncSession`'s `onCompletion`, which executes in a collector
     * that has *already been cancelled* on every user cancel, every cancelAndJoin restart, and
     * every view-model clear mid-sync. So stopping has to work from a cancelled context.
     *
     * This is a regression test with teeth: `stopTransferServer` suspends now (it moved to
     * `stopSuspend` to stop freezing Main for the grace period), and a plain
     * `withContext(default)` there calls `ensureActive()` and throws *without running its block*
     * in a cancelled coroutine. The server would then hold the port for the rest of the process
     * and never release its lease — turning the single most common user action, cancelling a sync,
     * into a permanent leak. The old blocking stop() had no suspension point and could not fail
     * this way, so making it suspend is precisely what created the hazard.
     */
    @Test
    fun stopFromAnAlreadyCancelledCoroutineStillTearsTheServerDown() = runBlocking {
        repository.startTransferServer()
        Socket("127.0.0.1", DATA_PORT).use { socket ->
            assertTrue(socket.isConnected, "the server must be up before the cancellation path runs")
        }

        // Mirror the production shape exactly: `runSyncSession`'s `onCompletion { if (started)
        // transferRepository.stopTransferServer() }` calls this bare, with no NonCancellable of
        // its own - it relies entirely on `stopTransferServer()`'s own internal
        // `withContext(NonCancellable + ...)` to survive running inside an already-cancelled
        // collector. Wrapping the call here in the test's own `withContext(NonCancellable)` would
        // mask exactly the regression this test exists to catch: with that wrapper, a regressed
        // `stopTransferServer` using a plain `withContext(default)` would still run to completion,
        // because the wrapper's own job is never cancelled and `ensureActive()` inside it passes -
        // so the test would keep passing with the fix reverted. Calling it bare is what makes the
        // assertion below actually depend on the production NonCancellable staying in place.
        // The job must actually reach awaitCancellation() before it is cancelled. `launch` on
        // Dispatchers.Default is dispatched asynchronously, so cancelling straight after it can
        // kill the coroutine before its body ever runs — the `finally` never executes, the server
        // is never stopped, and the test fails for a reason that has nothing to do with what it is
        // meant to be checking.
        val entered = CompletableDeferred<Unit>()
        val job = launch(Dispatchers.Default) {
            try {
                entered.complete(Unit)
                awaitCancellation()
            } finally {
                repository.stopTransferServer()
            }
        }
        entered.await()
        job.cancelAndJoin()

        assertPortFree()
    }

    /**
     * Proves nothing is still listening, by connecting and requiring a refusal.
     *
     * Deliberately not "bind the port and see if it works". The server binds a wildcard connector,
     * and on BSD/macOS a loopback bind with SO_REUSEADDR can succeed *while that wildcard socket is
     * still listening* — so the bind-based probe this replaces could report a freed port over a
     * server that had never come down, which is a false pass in the one assertion that exists to
     * catch a leaked server. Refusing a connection is unambiguous, and unlike a bind it cannot trip
     * over TIME_WAIT from the test's own client sockets.
     */
    private fun assertPortFree() {
        assertTrue(
            awaitPortFree(),
            "a server is still listening on $DATA_PORT - teardown did not happen",
        )
    }

    /**
     * Polls until nothing accepts on the data port, up to [timeoutMs].
     *
     * Netty's graceful stop returns once it has run the quiet period, but the listening socket can
     * take a moment longer to actually stop accepting. A single instantaneous probe therefore
     * races the shutdown, and — because Netty binds with SO_REUSEADDR — a *following* test can bind
     * its own server alongside one that has not finished closing, leaving two live servers where
     * this fixture assumes one. That failure surfaces in whichever test happens to run next rather
     * than the one that caused it, which is the worst possible place for it to appear.
     */
    private fun awaitPortFree(timeoutMs: Long = 5_000): Boolean {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000
        while (System.nanoTime() < deadline) {
            val refused = runCatching {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", DATA_PORT), 250) }
            }.isFailure
            if (refused) return true
            Thread.sleep(25)
        }
        return false
    }

    // ------------------------------------------------------------------ fakes

    /** A transfer scope whose dispatcher drops every task: queued work never runs. */
    private class NeverRunsTransferScope : CoroutineScopeFacade {
        private val neverDispatcher = object : CoroutineDispatcher() {
            override fun dispatch(context: CoroutineContext, block: Runnable) {
                // Deliberately dropped: the transfer server lifecycle must not depend on this scope.
            }
        }
        override val globalScope = CoroutineScope(Dispatchers.Unconfined + SupervisorJob())

        // The setter ignores writes on purpose. `startTransferServer` reassigns `transferScope` to
        // a real scope on every fresh start, so with a plain `var` this fixture would hand back a
        // working dispatcher the moment it was asked to — and the guarantee below would quietly
        // stop holding. Ignoring the write keeps the dropping dispatcher in place for the whole
        // test, which is what makes a regression to a launched start fail these assertions outright
        // on a refused connection rather than pass on lucky timing.
        override var transferScope = CoroutineScope(neverDispatcher + SupervisorJob())
            set(value) { /* ignored - see above */ }
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
        override suspend fun getSessionId(): String = "transfer-server-lifecycle"
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
}
