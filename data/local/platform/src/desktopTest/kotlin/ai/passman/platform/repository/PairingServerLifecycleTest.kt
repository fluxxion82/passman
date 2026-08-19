package ai.passman.platform.repository

import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.repository.FileTransferRepository.Companion.PAIRING_PORT
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
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.runBlocking

/**
 * The pairing listener's start/stop contract, which the Trusted Devices screen depends on for its
 * stop-then-start restart around every ceremony and for teardown:
 *
 * - when `startPairingServer` returns, the listener is actually accepting connections;
 * - when `stopPairingServer` returns, nothing is left holding the port.
 *
 * The transfer scope in this fixture deliberately never executes anything it is handed. If the
 * pairing lifecycle delegates to a launched coroutine again, start/stop return values stop meaning
 * anything: a stop can run before a queued start executes, leaking a plaintext listener that no
 * later stop can reach.
 */
class PairingServerLifecycleTest {

    private lateinit var root: File
    private lateinit var repository: FileTransferRepository

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("pairing-server-lifecycle").toFile()
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
        runBlocking { repository.stopPairingServer() }
        root.deleteRecursively()
    }

    @Test
    fun startIsListeningWhenItReturnsAndStopReleasesThePort() = runBlocking {
        repository.startPairingServer()
        Socket("127.0.0.1", PAIRING_PORT).use { socket ->
            assertTrue(socket.isConnected, "listener must accept connections once start returns")
        }

        repository.stopPairingServer()
        assertPortFree()
    }

    @Test
    fun rapidRestartsNeverLeakAListener() = runBlocking {
        // The ViewModel restarts the listener at every ceremony boundary (begin/confirm/cancel).
        repeat(3) {
            repository.startPairingServer()
            repository.stopPairingServer()
        }

        repository.startPairingServer()
        Socket("127.0.0.1", PAIRING_PORT).use { socket ->
            assertTrue(socket.isConnected)
        }
        repository.stopPairingServer()
        assertPortFree()
    }

    /** Binding the fixed pairing port proves no forgotten listener still holds it. */
    private fun assertPortFree() {
        ServerSocket().use { probe ->
            probe.reuseAddress = true
            probe.bind(InetSocketAddress("127.0.0.1", PAIRING_PORT))
        }
    }

    // ------------------------------------------------------------------ fakes

    /** A transfer scope whose dispatcher drops every task: queued work never runs. */
    private class NeverRunsTransferScope : CoroutineScopeFacade {
        private val neverDispatcher = object : CoroutineDispatcher() {
            override fun dispatch(context: CoroutineContext, block: Runnable) {
                // Deliberately dropped: the pairing lifecycle must not depend on this scope.
            }
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
        override suspend fun getSessionId(): String = "pairing-server-lifecycle"
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
