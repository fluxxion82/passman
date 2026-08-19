package ai.passman.platform.connectivity

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.impl.LocalTrustedDevicesRepository
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.BeginDevicePairing
import ai.passman.domain.connectivity.CancelDevicePairing
import ai.passman.domain.connectivity.ConfirmDevicePairing
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.PendingPairingState
import ai.passman.domain.connectivity.QrPairingSession
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.persistences.InMemoryUserEventsPersistence
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.MapSettings
import com.russhwolf.settings.Settings
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.CoroutineContext
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@OptIn(ExperimentalEncodingApi::class)
class ManualPairingTest {
    @Test
    fun beginPairing_exchangesPublicBundlesAndPersistsNothingUntilConfirmation() = runBlocking {
        val local = bundle(0x11)
        val peer = bundle(0x22)
        val fingerprintService = FakeFingerprintService(local, peer)
        val repository = FakeTrustedDevicesRepository()
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, SwitchableUser("ster"))

        val result = begin(BeginDevicePairing.Parameters(host = "192.0.2.10"))

        val pairing = assertIs<Outcome.Success<*>>(result).value as ai.passman.domain.connectivity.PendingPairing
        assertEquals("192.0.2.10", pairing.peerAddress)
        assertContentEquals(Json.encodeToString(peer).encodeToByteArray(), pairing.peerBundleBytes)
        assertEquals(local.safetyNumber(peer, fingerprintService), pairing.safetyNumber)
        assertEquals(0, repository.devices.size)
        assertEquals(local, fingerprintService.pushedBundle)
        assertNull(
            fingerprintService.pushedProof,
            "a ceremony no code started sends the same push it always did",
        )
    }

    @Test
    fun confirmation_upgradesExistingPairWithoutReplacingItsRsaSpkiPin() = runBlocking {
        val local = bundle(0x11)
        val peer = bundle(0x22)
        val fingerprintService = FakeFingerprintService(local, peer)
        val repository = FakeTrustedDevicesRepository(
            TrustedDevice(
                name = "desktop",
                fingerprint = "FROZEN-RSA-SPKI-PIN",
                lastHost = "192.0.2.10",
                pairingSecurity = PairingSecurity.LegacyRsa,
            ),
        )
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))
        val confirmed = assertIs<Outcome.Success<*>>(confirm(ConfirmDevicePairing.Parameters("desktop"))).value
            as TrustedDevice

        assertEquals("FROZEN-RSA-SPKI-PIN", confirmed.fingerprint)
        assertEquals(PairingSecurity.SignedHybridRequired, confirmed.pairingSecurity)
        assertEquals(fingerprintService.fingerprintOf(peer.canonicalEncoding()), confirmed.identityDigest)
        assertEquals(peer.hybridPublicKey.encodeBase64(), confirmed.hybridPublicKey)
        assertEquals(peer.mldsaPublicKey.encodeBase64(), confirmed.mldsaPublicKey)
        assertNull(pending.active(PairingOwner.current(preferences)))
    }

    @Test
    fun confirmation_fingerprintsReceivedRsaSpkiForBrandNewPair() = runBlocking {
        val local = bundle(0x11)
        val peer = bundle(0x23)
        val fingerprintService = FakeFingerprintService(local, peer)
        val repository = FakeTrustedDevicesRepository()
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.11")))
        val confirmed = assertIs<Outcome.Success<*>>(confirm(ConfirmDevicePairing.Parameters("new desktop"))).value
            as TrustedDevice

        assertEquals(fingerprintService.fingerprintOf(peer.rsaSpki), confirmed.fingerprint)
        assertEquals(PairingSecurity.SignedHybridRequired, confirmed.pairingSecurity)
        assertEquals(1, repository.devices.size)
    }

    @Test
    fun confirmation_doesNotInheritAnotherDevicesPinWhenAddressWasRecycled() = runBlocking {
        val local = bundle(0x11)
        val peer = bundle(0x24)
        val fingerprintService = FakeFingerprintService(local, peer)
        // A stale record for a DIFFERENT device that once lived at the address the new device now
        // occupies (DHCP reuse). Its frozen pin must not leak onto the brand-new pairing.
        val repository = FakeTrustedDevicesRepository(
            TrustedDevice(
                name = "old laptop",
                fingerprint = "STALE-DEVICE-PIN",
                lastHost = "192.0.2.12",
                pairingSecurity = PairingSecurity.LegacyRsa,
            ),
        )
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.12")))
        val confirmed = assertIs<Outcome.Success<*>>(confirm(ConfirmDevicePairing.Parameters("new phone"))).value
            as TrustedDevice

        assertEquals(fingerprintService.fingerprintOf(peer.rsaSpki), confirmed.fingerprint)
        assertEquals(2, repository.devices.size)
        assertEquals(
            "STALE-DEVICE-PIN",
            repository.devices.first { it.name == "old laptop" }.fingerprint,
        )
    }

    /**
     * A pairing the store refused is not a pairing, and the user must not be told otherwise.
     *
     * By the time confirmation runs, `BeginDevicePairing` has already pushed our bundle to the
     * peer, so the peer's side can complete and trust us. If our own write is dropped — nobody
     * signed in, the account moved underneath the ceremony, an encrypted store that would not
     * initialise — and this still reports success, the screen shows "Confirmed" for a device that
     * exists on exactly one of the two machines: the peer syncs to us and we reject it, with
     * nothing on screen to explain why. So the failure is reported, and the pending exchange is
     * *kept*: clearing it would make the retry a whole fresh ceremony (fetch, push, and the human
     * comparing the safety number again) instead of pressing Confirm a second time.
     *
     * Kept for the account that ran it, and only that one — see
     * [confirmation_cannotBeRetriedUnderAnAccountThatDidNotRunTheCeremony].
     */
    @Test
    fun confirmation_reportsFailureAndKeepsThePendingExchangeWhenTheStoreRefusesTheWrite() = runBlocking {
        val local = bundle(0x11)
        val peer = bundle(0x22)
        val fingerprintService = FakeFingerprintService(local, peer)
        val repository = FakeTrustedDevicesRepository()
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))
        repository.acceptsAdds = false

        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertEquals(0, repository.devices.size, "precondition: the write really was dropped")
        assertNotNull(
            pending.active(PairingOwner.current(preferences)),
            "the compared exchange must survive a refused write so Confirm can be pressed again",
        )

        // The retry runs against that same pending exchange — no second ceremony, no re-comparison.
        // Same account, same session: the ceremony's own owner is the one spending it.
        repository.acceptsAdds = true
        val confirmed = assertIs<Outcome.Success<*>>(confirm(ConfirmDevicePairing.Parameters("desktop"))).value
            as TrustedDevice

        assertEquals(listOf(confirmed), repository.devices.toList(), "the retry is what persists the pairing")
        assertEquals(PairingSecurity.SignedHybridRequired, confirmed.pairingSecurity)
        assertNull(
            pending.active(PairingOwner.current(preferences)),
            "and only a stored pairing clears the exchange",
        )
    }

    /**
     * A retained exchange is not a bearer token for whoever signs in next.
     *
     * The refused write above leaves the compared exchange in place so Confirm can be pressed
     * again. Unbound, that is a cross-account trust injection waiting to happen: press Confirm as
     * A, have the write refused (the account moved underneath it, the store would not initialise —
     * the store answers `false` either way), sign in as B, press Confirm again, and the store's own
     * guard sees nothing wrong because B is signed in and B is writing. What lands in B's store is
     * account A's peer material — the mTLS SPKI pin and PQ public keys only A's ceremony ever
     * attested to — and that store is what the receive side authorizes inbound sync against, so B
     * now admits a device it never met.
     *
     * The switch here is the one nothing downstream can spot on its own: a `LoginUser` with no
     * logout in between, which leaves the session id untouched while the account moves.
     */
    @Test
    fun confirmation_cannotBeRetriedUnderAnAccountThatDidNotRunTheCeremony() = runBlocking {
        val fingerprintService = FakeFingerprintService(bundle(0x11), bundle(0x22))
        val stores = AccountStores()
        val preferences = SwitchableUser("ster")
        val repository = accountScopedRepository(stores, preferences)
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))

        // The store refuses the write: a per-account store is withheld until its first-touch wipe
        // goes through — once for the read the confirmation does, once for the write itself.
        stores.failClears(STER_STORE, times = 2)
        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertNull(stores.devicesIn(STER_STORE), "precondition: the write really was refused")
        assertNotNull(
            pending.active(PairingOwner("ster", preferences.sessionId)),
            "precondition: the refused write keeps the exchange, which is what makes a replay possible",
        )

        preferences.signIn("work")

        val replay = confirm(ConfirmDevicePairing.Parameters("desktop"))
        assertNull(stores.devicesIn(WORK_STORE), "and its store must never hold the other account's peer material")
        assertIs<Outcome.Error>(
            replay,
            "the account that took over never ran this ceremony and must not be able to spend it",
        )
        assertNull(stores.devicesIn(STER_STORE), "nor may the write be filed back under the account that is gone")
        assertNull(
            pending.active(PairingOwner("ster", preferences.sessionId)),
            "a replay attempt drops the exchange rather than leaving it on offer to the next account",
        )
    }

    /**
     * Same account, different login: the session id is the half that catches it.
     *
     * `LogoutUser` clears the session and only a completed login mints another, so an exchange
     * begun before that logout has its provenance in a login that no longer exists — the keystore
     * the peer attested against has been through a lock/unlock cycle in between. The account name
     * alone cannot tell the two logins apart.
     */
    @Test
    fun confirmation_cannotBeRetriedAfterTheLoginItWasBegunUnderEnded() = runBlocking {
        val fingerprintService = FakeFingerprintService(bundle(0x11), bundle(0x22))
        val stores = AccountStores()
        val preferences = SwitchableUser("ster")
        val repository = accountScopedRepository(stores, preferences)
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))
        stores.failClears(STER_STORE, times = 2)
        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertNull(stores.devicesIn(STER_STORE), "precondition: the write really was refused")

        preferences.logoutAndSignIn("ster")

        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertNull(stores.devicesIn(STER_STORE), "a ceremony outlives neither the login that ran it nor its session")
    }

    /**
     * The interleave the two guards used to hide from each other.
     *
     * There were two independent pairs of samples of "who is signed in": the confirmation checking
     * the account it started under against a re-sample taken just before the write, and the store
     * checking the account it entered with against the one it resolved under its lock. Neither pair
     * spanned the gap between them. A `LoginUser` with no logout — the switch that moves the account
     * and leaves the session id untouched — landing in that gap leaves the confirmation having seen
     * A twice and the store having seen B twice, both satisfied, and account A's peer material
     * written into account B's store: the mTLS pin and PQ keys inbound sync is authorized against,
     * for a device B never met. Two agreeing samples of the current account say nothing about which
     * account the material belongs to.
     *
     * So the write carries the ceremony's own owner and the store compares *that* under its lock.
     * There is no gap left to land in: wherever the switch falls, the write is either refused or
     * filed under the account that attested to it.
     */
    @Test
    fun confirmation_isRefusedWhenTheAccountMovesBetweenItsOwnCheckAndTheStoresWrite() = runBlocking<Unit> {
        val fingerprintService = FakeFingerprintService(bundle(0x11), bundle(0x22))
        val stores = AccountStores()
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState()
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(
            // The login lands after the confirmation has checked the owner and read the store, and
            // before the store takes the lock it resolves the account under.
            trustedDevices = signingInAfterTheConfirmationReads(
                accountScopedRepository(stores, preferences),
            ) { preferences.signIn("work") },
            fingerprintService = fingerprintService,
            pendingPairingState = pending,
            userPreferences = preferences,
        )

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))

        val result = confirm(ConfirmDevicePairing.Parameters("desktop"))

        assertIs<Outcome.Error>(result, "a write the store refused is not a pairing, whoever pressed Confirm")
        assertNull(
            stores.devicesIn(WORK_STORE),
            "the account that took over never ran this ceremony and must not be handed its peer material",
        )
        assertNull(stores.devicesIn(STER_STORE), "nor may it be filed under an account that is no longer signed in")
        assertNotNull(
            pending.active(PairingOwner("ster", preferences.sessionId)),
            "and the refused write leaves the exchange to the account that began it",
        )
    }

    @Test
    fun cancellationAndTimeout_clearPendingPairingWithoutPersistingAwaitingConfirmation() = runBlocking {
        var nowMs = 1_000L
        val local = bundle(0x11)
        val peer = bundle(0x22)
        val fingerprintService = FakeFingerprintService(local, peer)
        val repository = FakeTrustedDevicesRepository()
        val preferences = SwitchableUser("ster")
        val pending = PendingPairingState(nowMs = { nowMs }, timeoutMs = 10)
        val begin = BeginDevicePairing(fingerprintService, pending, preferences)
        val confirm = ConfirmDevicePairing(repository, fingerprintService, pending, preferences)
        val cancel = CancelDevicePairing(pending, QrPairingSession(fingerprintService, pending))

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))
        cancel(Unit)
        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertEquals(0, repository.devices.size)

        assertIs<Outcome.Success<*>>(begin(BeginDevicePairing.Parameters("192.0.2.10")))
        nowMs += 11
        assertIs<Outcome.Error>(confirm(ConfirmDevicePairing.Parameters("desktop")))
        assertEquals(0, repository.devices.size)
        assertNull(pending.active(PairingOwner.current(preferences)))
    }

    /**
     * [real], with a sign-in landing in the one window a confirmation cannot close from outside:
     * after the read it does to build the device, before the write it then asks for. Everything the
     * store decides about the account — which store to open, whose write this is — happens inside
     * that write, under its own lock, so this is the moment where a caller-side check and a
     * store-side check are each looking at the wrong side of the switch.
     */
    private fun signingInAfterTheConfirmationReads(
        real: TrustedDevicesRepository,
        signIn: () -> Unit,
    ): TrustedDevicesRepository = object : TrustedDevicesRepository by real {
        override suspend fun getAll(): List<TrustedDevice> = real.getAll().also { signIn() }
    }

    /** The production store, over in-memory settings: per-account files, resolved per call. */
    private fun accountScopedRepository(stores: AccountStores, preferences: UserPreferences) =
        LocalTrustedDevicesRepository(
            encryptedFactory = stores,
            userPreferences = preferences,
            userEvents = InMemoryUserEventsPersistence(UnconfinedFacade),
            coroutinesContextFacade = UnconfinedFacade,
        )

    private fun bundle(seed: Int): DeviceIdentityBundle = DeviceIdentityBundle(
        rsaSpki = ByteArray(294) { seed.toByte() },
        hybridPublicKey = ByteArray(32 + 2 + 1_184) { seed.toByte() }.also {
            it[32] = (1_184 ushr 8).toByte()
            it[33] = 1_184.toByte()
        },
        mldsaPublicKey = ByteArray(1_952) { seed.toByte() },
        capabilityBits = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
    )

    private class FakeFingerprintService(
        private val local: DeviceIdentityBundle,
        private val peer: DeviceIdentityBundle,
    ) : FingerprintService {
        var pushedBundle: DeviceIdentityBundle? = null
        var pushedProof: String? = null
        private var draws = 0

        override fun digest(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
            Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

        /**
         * Predictable where the real service is unpredictable — a test asserting on a nonce needs to
         * know it — but never the same bytes twice. A draw that repeated would make a QR that
         * reshows the retired nonce, or a session that never rotates one, look exactly like a
         * working one.
         */
        override fun randomBytes(count: Int): ByteArray {
            val draw = draws++
            return ByteArray(count) { (it + draw).toByte() }
        }

        override fun fingerprintOf(publicKeyBytes: ByteArray): String =
            digest(publicKeyBytes).joinToString(":") { "%02X".format(it.toInt() and 0xFF) }

        override suspend fun getOwnFingerprint(): Outcome<String> = Outcome.Success(fingerprintOf(local.rsaSpki))

        override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> =
            Outcome.Success(fingerprintOf(peer.rsaSpki))

        override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = Outcome.Success(local)

        override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> = Outcome.Success(peer)

        override suspend fun pushDeviceIdentityBundle(
            bundle: DeviceIdentityBundle,
            host: String,
            port: Int,
            proofBase64Url: String?,
        ): Outcome<Unit> {
            pushedBundle = bundle
            pushedProof = proofBase64Url
            return Outcome.Success(Unit)
        }
    }

    private class FakeTrustedDevicesRepository(vararg initial: TrustedDevice) : TrustedDevicesRepository {
        val devices = initial.toMutableList()

        /**
         * Whether [add] accepts the write. The real store refuses one whenever no account is signed
         * in, the account moved underneath the operation, or its encrypted store will not
         * initialise — all of which answer false rather than throwing.
         */
        var acceptsAdds = true

        override fun observeAll(): Flow<List<TrustedDevice>> = flowOf(devices.toList())

        override suspend fun getAll(): List<TrustedDevice> = devices.toList()

        override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean {
            if (!acceptsAdds) return false
            devices.removeAll { it.name == device.name }
            devices += device
            return true
        }

        override suspend fun remove(name: String) {
            devices.removeAll { it.name == name }
        }

        override suspend fun getByHost(host: String): TrustedDevice? = devices.firstOrNull { it.lastHost == host }

        override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit

        override suspend fun updateHost(name: String, host: String) = Unit

        override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit

        override suspend fun markSignedHybridPairingsForReverification() = Unit
    }

    /** Name-keyed encrypted stores, the way both platform factories behave: one name, one node. */
    private class AccountStores : EncryptionSettingsFactory {
        private val stores = mutableMapOf<String, MapSettings>()
        private val failingClears = mutableMapOf<String, Int>()

        override fun createEncrypted(name: String): Settings = Guarded(name, stores.getOrPut(name) { MapSettings() })

        /** The device list [name] holds on disk, or null when it holds none at all. */
        fun devicesIn(name: String): String? = stores[name]?.getStringOrNull(DEVICES_KEY)

        /** Makes the next [times] `clear()` calls on [name] fail, the way a prefs node can. */
        fun failClears(name: String, times: Int) {
            failingClears[name] = times
        }

        private inner class Guarded(private val name: String, private val delegate: MapSettings) :
            Settings by delegate {
            override fun clear() {
                val remaining = failingClears[name] ?: 0
                if (remaining > 0) {
                    failingClears[name] = remaining - 1
                    error("simulated encrypted store failure clearing '$name'")
                }
                delegate.clear()
            }
        }
    }

    /**
     * Who is signed in, with `LocalUserPreferences`' session behaviour: a logout drops the session
     * id and the next login mints a fresh one, while the stored user name survives it.
     */
    private class SwitchableUser(userName: String) : UserPreferences {
        private var name = userName
        private var minted = 1

        var sessionId: String = "session-1"
            private set

        /** A `LoginUser` with no logout in between: the account changes, the session id does not. */
        fun signIn(userName: String) {
            name = userName
        }

        /** A logout and a login: `LogoutUser` clears the session, and the login mints the next one. */
        fun logoutAndSignIn(userName: String) {
            name = userName
            sessionId = "session-${++minted}"
        }

        override suspend fun getUser(): AppUser = AppUser.LoggedIn(name, CREDENTIAL)
        override suspend fun getSessionId(): String = sessionId

        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun clear() {
            sessionId = "session-${++minted}"
        }

        private companion object {
            val CREDENTIAL = Password(hash = "hash", salt = "salt")
        }
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }

    private fun ByteArray.encodeBase64(): String = Base64.Default.encode(this)

    private companion object {
        const val STER_STORE = "trusted_devices_ster"
        const val WORK_STORE = "trusted_devices_work"
        const val DEVICES_KEY = "devices"
    }
}
