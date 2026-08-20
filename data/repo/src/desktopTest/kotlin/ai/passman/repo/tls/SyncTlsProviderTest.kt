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
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
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

    /**
     * A fingerprint is the peer's long-term identity, not a property of one pairing, so re-pairing
     * the same physical device under a new name leaves two records carrying it. `authorize` used to
     * decide against whichever came first, which meant an op one record's `allowedOps` refused
     * could be granted by the other — and, worse, that the same arbitrary choice picked the inbound
     * decryption policy. Ambiguity is refused, matching what `getByHost` does on the send side.
     */
    @Test
    fun `authorization refuses a pin that two pairings share`() = runBlocking {
        val devices = RecordingTrustedDevices(
            listOf(
                TrustedDevice(
                    name = "phone",
                    fingerprint = "AA:BB:CC:DD",
                    lastHost = "192.0.2.44",
                    allowedOps = setOf(SyncOps.PASSWORDS),
                    pairingSecurity = PairingSecurity.LegacyRsa,
                ),
                TrustedDevice(
                    name = "phone (re-paired)",
                    fingerprint = "AA:BB:CC:DD",
                    lastHost = "192.0.2.44",
                    allowedOps = setOf(SyncOps.PASSWORDS),
                    pairingSecurity = PairingSecurity.SignedHybridRequired,
                ),
            ),
        )
        val provider = SyncTlsProvider(FakePreferences(), devices)

        assertFalse(
            provider.authorize(SyncOps.PASSWORDS, "aabbccdd"),
            "an op must not be granted on the strength of whichever duplicate pairing sorted first",
        )
        assertNull(provider.deviceForPin("aabbccdd"))
        assertEquals(2, provider.devicesForPin("aabbccdd").size, "both records still match the pin")
    }

    /**
     * The pin follows the record the caller hands over, not the address it happens to sit at.
     *
     * Two pairings can hold one `lastHost` — [TrustedDevice] has no id, so re-pairing or an edited
     * address is enough — and pinning the wrong one of the two fails the handshake outright. That is
     * the failure a user would see after correctly editing the address of the device they *did*
     * want: sync stays broken for it while nothing on screen explains why. Here the two records
     * carry different fingerprints, so the pin says unambiguously which record was used.
     */
    @Test
    fun `clientTls pins the device it is given, not the first record at that address`() = runBlocking {
        val first = TrustedDevice(name = "desktop", fingerprint = "AA:BB:CC:DD", lastHost = SHARED_HOST)
        val chosen = TrustedDevice(name = "desktop-re-paired", fingerprint = "11:22:33:44", lastHost = SHARED_HOST)
        val provider = SyncTlsProvider(FakePreferences(), RecordingTrustedDevices(listOf(first, chosen)))

        assertEquals(
            setOf("11223344"),
            assertNotNull(provider.clientTls(chosen)).serverPins,
            "the chosen record's SPKI must be pinned; the first record at that address would pin aabbccdd",
        )
        assertEquals(setOf("aabbccdd"), assertNotNull(provider.clientTls(first)).serverPins)
    }

    /**
     * The typed-address overload has no record to follow, so an address two pairings claim resolves
     * to neither rather than to whichever came first — a coin-flip pin the user could not see.
     */
    @Test
    fun `clientTls for a typed address refuses one that two pairings claim`() = runBlocking {
        val devices = RecordingTrustedDevices(
            listOf(
                TrustedDevice(name = "desktop", fingerprint = "AA:BB:CC:DD", lastHost = SHARED_HOST),
                TrustedDevice(name = "desktop-re-paired", fingerprint = "11:22:33:44", lastHost = SHARED_HOST),
            ),
        )
        val provider = SyncTlsProvider(FakePreferences(), devices)

        assertNull(provider.clientTls(SHARED_HOST))
        assertNull(provider.deviceForHost(SHARED_HOST))
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
        /** Mirrors production: one match or nothing, never a first match. */
        override suspend fun getByHost(host: String): TrustedDevice? =
            devices.filter { it.lastHost == host }.singleOrNull()
        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
        override suspend fun updateHost(name: String, host: String) = Unit
        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
        override suspend fun markSignedHybridPairingsForReverification() {
            reverificationCalls++
        }
    }

    private companion object {
        const val SHARED_HOST = "192.0.2.44"
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
