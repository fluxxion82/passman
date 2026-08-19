package ai.passman.repo.tls

import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module

class SyncTlsProviderTest {
    private val identity: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    @BeforeTest
    fun setUp() {
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped<Key>(named(PRIVATE_DECRYPTION_KEY)) { identity.private }
                        scoped<Key>(named(PUBLIC_ENCRYPTION_KEY)) { identity.public }
                    }
                },
            )
        }
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
    }

    @Test
    fun `TLS pinning and authorization continue to use the frozen SPKI fingerprint not the display digest`() = runBlocking {
        val devices = RecordingTrustedDevices(
            listOf(
                TrustedDevice(
                    name = "desktop",
                    fingerprint = "AA:BB:CC:DD",
                    lastHost = "192.0.2.44",
                    identityDigest = "composite-display-digest-must-never-be-a-pin",
                    pairingSecurity = PairingSecurity.SignedHybridRequired,
                ),
            ),
        )
        val provider = SyncTlsProvider(FakePreferences(), devices)

        val server = assertNotNull(provider.serverTls())
        val client = assertNotNull(provider.clientTls("192.0.2.44"))

        assertEquals(setOf("aabbccdd"), server.allowedClientPins)
        assertEquals(setOf("aabbccdd"), client.serverPins)
        assertTrue(provider.authorize(SyncOps.PASSWORDS, "aabbccdd"))
        assertEquals(0, devices.reverificationCalls)
    }

    private class RecordingTrustedDevices(
        private val devices: List<TrustedDevice>,
    ) : TrustedDevicesRepository {
        var reverificationCalls = 0
            private set

        override fun observeAll(): Flow<List<TrustedDevice>> = flowOf(devices)
        override suspend fun getAll(): List<TrustedDevice> = devices
        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
        override suspend fun remove(name: String) = Unit
        override suspend fun getByHost(host: String): TrustedDevice? = devices.firstOrNull { it.lastHost == host }
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
        override suspend fun updateHost(name: String, host: String) = Unit
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
        override suspend fun markSignedHybridPairingsForReverification() {
            reverificationCalls++
        }
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("password", "salt"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "sync-tls-provider-test"
        override suspend fun clear() = Unit
    }
}
