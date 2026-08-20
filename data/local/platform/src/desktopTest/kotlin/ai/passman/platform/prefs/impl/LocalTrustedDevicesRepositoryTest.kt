package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.InMemoryUserEventsPersistence
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.MapSettings
import com.russhwolf.settings.Settings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json

/**
 * Account scoping of trusted-device pairings.
 *
 * A pairing pins the peer to the identity in `keystore/<user>/`, so an entry paired under one
 * account can never authenticate for another — the device-global store this replaces both showed
 * account B account A's device names/hosts/sync times and offered it entries that were already
 * dead for it. These tests hold three things: each account reads and writes only its own store,
 * the pre-scoping global store is dropped rather than attributed, and a live observer follows a
 * logout/login to a different account inside one process.
 *
 * They also hold the security edges around that scoping: a logged-out process resolves no account
 * at all (the stored user name outlives the logout, and this store gates sync), a mutation that
 * races an account switch or a reissued session lands in no store at all and says so, and a store
 * whose first-touch wipe fails is withheld rather than served with whatever it was seeded from.
 */
class LocalTrustedDevicesRepositoryTest {

    private val laptop = TrustedDevice(name = "laptop", fingerprint = "fp-laptop", lastHost = "192.0.2.10")
    private val phone = TrustedDevice(name = "phone", fingerprint = "fp-phone", lastHost = "192.0.2.11")
    private val leaked = TrustedDevice(name = "leaked", fingerprint = "fp-leaked", lastHost = "192.0.2.99")

    @Test
    fun `a pairing made under one account is invisible to another`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        assertTrue(
            devices.add(laptop, PairingOwner.current(preferences)),
            "a write that reached the account's store reports success",
        )
        assertEquals(listOf(laptop), devices.getAll())

        preferences.signIn("work")
        assertEquals(emptyList(), devices.getAll(), "account 2 must not see account 1's pairings")
        assertNull(devices.getByHost(laptop.lastHost), "nor resolve them by host on the sync path")

        preferences.signIn("ster")
        assertEquals(listOf(laptop), devices.getAll(), "switching back must find the account's own list")
    }

    @Test
    fun `each account keeps its own pairings when both have paired`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        devices.add(laptop, PairingOwner.current(preferences))
        preferences.signIn("work")
        devices.add(phone, PairingOwner.current(preferences))

        assertEquals(listOf(phone), devices.getAll())
        preferences.signIn("ster")
        assertEquals(listOf(laptop), devices.getAll(), "the second account's write must not touch the first's store")

        // Removal is scoped too: the name exists under the other account only.
        devices.remove(phone.name)
        assertEquals(listOf(laptop), devices.getAll())
        preferences.signIn("work")
        assertEquals(listOf(phone), devices.getAll(), "a remove under one account must not reach into another")
    }

    @Test
    fun `updateHost repoints only the named device and leaves everything else alone`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        val syncedLaptop = laptop.copy(lastSyncedAt = 111L)
        val syncedPhone = phone.copy(lastSyncedAt = 222L)
        devices.add(syncedLaptop, PairingOwner.current(preferences))
        devices.add(syncedPhone, PairingOwner.current(preferences))

        devices.updateHost(laptop.name, "10.0.0.9")

        assertEquals(
            listOf(syncedLaptop.copy(lastHost = "10.0.0.9"), syncedPhone),
            devices.getAll(),
            "only the named device's address moves; its sync time and the other device stay put",
        )

        devices.updateHost("unknown", "10.0.0.77")
        assertEquals(
            listOf(syncedLaptop.copy(lastHost = "10.0.0.9"), syncedPhone),
            devices.getAll(),
            "an unknown name is a no-op",
        )
    }

    /**
     * An address is not an identity, and this store never promised it was: [TrustedDevice] has no
     * id, `add` dedupes on [TrustedDevice.name] alone, and re-pairing the same physical peer under
     * a new name therefore leaves two rows holding the same `lastHost` *and* the same fingerprint.
     *
     * `getByHost` used to answer such a host with `firstOrNull`, so callers that re-derived a device
     * from an address — the last-sync stamp, the mTLS SPKI pin, the sync log's device name — could
     * act on a pairing the user never chose. Those callers now carry the chosen record instead, and
     * what is left of this method resolves a *typed* address, where a coin-flip between two
     * indistinguishable pairings is worse than an honest "that address names no single device": the
     * wrong pin fails the handshake for reasons the user cannot see.
     */
    @Test
    fun `a host claimed by two pairings resolves to neither, while one claimant still resolves`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        devices.add(laptop, PairingOwner.current(preferences))
        assertEquals(laptop, devices.getByHost(laptop.lastHost), "a single claimant still resolves")

        // The same peer, re-paired under a different name: same host, same fingerprint, second row.
        val rePairedLaptop = laptop.copy(name = "laptop-re-paired")
        devices.add(rePairedLaptop, PairingOwner.current(preferences))
        assertEquals(
            listOf(laptop, rePairedLaptop),
            devices.getAll(),
            "precondition: nothing stops two pairings from claiming one address",
        )

        assertNull(
            devices.getByHost(laptop.lastHost),
            "an address two pairings claim identifies neither of them; answering with the first is a " +
                "coin-flip the caller cannot see",
        )
        assertNull(devices.getByHost(phone.lastHost), "an address nobody claims still resolves to nothing")
    }

    /**
     * The other route to the same collision, and the reason it cannot be prevented at write time
     * without changing what `updateHost` means: repointing a device that moved on the LAN takes a
     * name and an address and checks nothing about who else is already there.
     */
    @Test
    fun `updateHost can move one pairing onto another's address, and the lookup then refuses`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        devices.add(laptop, PairingOwner.current(preferences))
        devices.add(phone, PairingOwner.current(preferences))
        assertEquals(phone, devices.getByHost(phone.lastHost))

        devices.updateHost(laptop.name, phone.lastHost)

        assertEquals(
            listOf(laptop.copy(lastHost = phone.lastHost), phone),
            devices.getAll(),
            "updateHost repoints by name and does not refuse an occupied address",
        )
        assertNull(devices.getByHost(phone.lastHost), "the shared address now identifies neither pairing")
        assertNull(devices.getByHost(laptop.lastHost), "and the address it moved off identifies nothing at all")
    }

    /**
     * The logout this mirrors is the production one, not a tidier one: `LogoutUser` announces
     * `LoginChanged(Anonymous)` and clears the session, and `LocalUserPreferences.clear()` only
     * drops the session id — `USER_NAME` stays behind so the login screen can prefill it. So
     * `getUser()` still answers "ster" here, exactly as it does on a logged-out device, and
     * anything that trusts it alone hands a still-running sync server the pins of an account
     * nobody is signed in to.
     */
    @Test
    fun `a logged out process resolves no account even though the user name survives`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val events = InMemoryUserEventsPersistence(UnconfinedFacade)
        val devices = repository(factory, preferences, events)

        devices.add(laptop, PairingOwner.current(preferences))
        assertEquals(listOf(laptop), devices.getAll())

        events.update(UserEvent.LoginChanged(AppUser.Anonymous))
        preferences.clear()

        assertEquals(
            "ster",
            (preferences.getUser() as? AppUser.LoggedIn)?.userName,
            "precondition: production keeps the user name across a logout",
        )
        assertEquals(emptyList(), devices.getAll(), "a logged-out process must not resolve the last account's list")
        assertNull(devices.getByHost(laptop.lastHost), "nor hand the sync authorizer a device for an inbound pin")
        assertEquals(emptyList(), devices.observeAll().first(), "and a live screen must render empty")

        assertFalse(
            devices.add(phone, PairingOwner.current(preferences)),
            "a write with nobody signed in reports the drop",
        )
        assertEquals(
            Json.encodeToString(listOf(laptop)),
            factory.store(STER_STORE).getStringOrNull(DEVICES_KEY),
            "a write with nobody signed in must be dropped, not attributed to the last account",
        )
    }

    @Test
    fun `the pre account scoping global store is dropped on first access`() = runBlocking {
        val factory = NamedStores()
        factory.seed(LEGACY_STORE, leaked)
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        assertEquals(emptyList(), devices.getAll(), "the un-attributable legacy list belongs to no account")
        assertNull(
            factory.store(LEGACY_STORE).getStringOrNull(DEVICES_KEY),
            "the leaked device-global list must be gone from disk, not merely ignored",
        )

        preferences.signIn("work")
        assertEquals(emptyList(), devices.getAll(), "and it must not resurface under any other account")
    }

    @Test
    fun `dropping the legacy store runs once and leaves later pairings alone`() = runBlocking {
        val factory = NamedStores()
        factory.seed(LEGACY_STORE, leaked)
        val preferences = SwitchableUser("ster")

        repository(factory, preferences).add(laptop, PairingOwner.current(preferences))

        // Second construction over the same stores: a process restart. The purge is stamped, so it
        // must not run again over a store that now holds real pairings.
        val restarted = repository(factory, preferences)
        assertEquals(listOf(laptop), restarted.getAll())
        assertNull(factory.store(LEGACY_STORE).getStringOrNull(DEVICES_KEY))
    }

    /** A purge that did not go through has not run, so the leaked list must not survive on a flag. */
    @Test
    fun `a failed purge of the legacy store is retried`() = runBlocking {
        val factory = NamedStores()
        factory.seed(LEGACY_STORE, leaked)
        factory.failClears(LEGACY_STORE, times = 1)
        val devices = repository(factory, SwitchableUser("ster"))

        assertEquals(emptyList(), devices.getAll())
        assertEquals(
            Json.encodeToString(listOf(leaked)),
            factory.store(LEGACY_STORE).getStringOrNull(DEVICES_KEY),
            "precondition: the first purge failed, so the un-attributable list is still there",
        )

        assertEquals(emptyList(), devices.getAll())
        assertNull(
            factory.store(LEGACY_STORE).getStringOrNull(DEVICES_KEY),
            "the next access must retry the purge rather than treat it as done",
        )
    }

    /**
     * A first touch is where a store gets wiped of whatever the platform factory seeded it with —
     * on desktop, a brand-new per-account node is filled from the pre-per-store-node flat prefs,
     * which is where the old device-global list lives. If that wipe does not go through, the store
     * is still holding the leaked list, so it must be withheld and retried, never served.
     */
    @Test
    fun `a store whose first touch fails is withheld and retried`() = runBlocking {
        val factory = NamedStores()
        factory.seed(STER_STORE, leaked)
        factory.failClears(STER_STORE, times = 2)
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)

        assertEquals(emptyList(), devices.getAll(), "a store that could not be wiped must not be read from")
        assertEquals(
            Json.encodeToString(listOf(leaked)),
            factory.store(STER_STORE).getStringOrNull(DEVICES_KEY),
            "precondition: the seeded list is still on disk — it was withheld, not wiped",
        )
        assertFalse(
            devices.add(phone, PairingOwner.current(preferences)),
            "a write into a withheld store must report failure, not silence",
        )
        assertEquals(
            Json.encodeToString(listOf(leaked)),
            factory.store(STER_STORE).getStringOrNull(DEVICES_KEY),
            "and a write must not land in a store that was never initialised",
        )

        // The failure was transient: the next access initialises the store, and the seeded list goes.
        assertEquals(emptyList(), devices.getAll())
        assertNull(
            factory.store(STER_STORE).getStringOrNull(DEVICES_KEY),
            "the retry wipes what the failed first touch could not",
        )
        assertTrue(
            devices.add(laptop, PairingOwner.current(preferences)),
            "and the store works normally from then on",
        )
        assertEquals(listOf(laptop), devices.getAll())
    }

    /**
     * The account switch that reuses the session is the one a session-id check cannot see.
     *
     * `LogoutUser` reissues the session, so comparing session ids catches "A logged out and B
     * logged in". It says nothing about a `LoginUser` that puts B in place with no logout in
     * between — the session id is untouched, and the write in flight is A's: an mTLS SPKI pin and
     * the peer's PQ public keys, gathered while A was signed in and attested to by A alone.
     * Committing it into B's store is not a misfiled row, it is B being handed trust in a device
     * only A ever met, which is exactly what this store gates the sync authorizer on. Both halves
     * of the owner — the account *and* the session — have to match, not either.
     */
    @Test
    fun `a mutation racing an account switch inside one session is dropped`() = runBlocking {
        val factory = NamedStores()
        val preferences = RacingUser(first = "ster", then = "work", switchAfterUserReads = 1)
        val devices = repository(factory, preferences)

        assertFalse(
            devices.add(laptop, PairingOwner.current(preferences)),
            "a write whose account moved underneath it must report failure",
        )

        assertTrue(
            WORK_STORE !in factory.stores,
            "the account that took the lock must not be handed the other account's peer material",
        )
        assertTrue(
            STER_STORE !in factory.stores,
            "and the account sampled before it is gone, so nothing lands there either",
        )
        assertTrue(
            factory.stores.values.none { it.getStringOrNull(DEVICES_KEY) != null },
            "a write whose owner changed underneath it belongs to no store",
        )
    }

    /**
     * A reissued session id is what a logout leaves behind (`LocalUserPreferences.clear()` drops it
     * and the next read mints a fresh one), so a write that started in one session and locked in
     * another was started by a login that is gone. Its peer material has stale provenance; it is
     * dropped rather than filed under whoever is signed in now.
     */
    @Test
    fun `a mutation racing a reissued session is dropped`() = runBlocking {
        val factory = NamedStores()
        val preferences = RacingUser(first = "ster", reissueAfterSessionReads = 1)
        val devices = repository(factory, preferences)

        assertFalse(
            devices.add(laptop, PairingOwner.current(preferences)),
            "a write whose session was reissued underneath it must report failure",
        )

        assertTrue(
            factory.stores.values.none { it.getStringOrNull(DEVICES_KEY) != null },
            "a write whose session was reissued underneath it belongs to no store",
        )
        assertEquals(emptyList(), devices.getAll())
    }

    /**
     * The mutators that take no owner sample one for themselves, and that sample is still checked.
     *
     * [LocalTrustedDevicesRepository.add] is told whose material it is carrying, so it is held to
     * that; [LocalTrustedDevicesRepository.remove] and the update mutators edit rows already filed
     * under an account and have nobody to ask, so they are held to the account they entered with.
     * A switch between that entry and the lock is the window they can still be caught in, and
     * losing this check would let one account's edit land in another's store.
     */
    @Test
    fun `an ownerless mutation racing an account switch is dropped`() = runBlocking {
        val factory = NamedStores()
        val devices = repository(factory, RacingUser(first = "ster", then = "work", switchAfterUserReads = 1))

        devices.remove(laptop.name)

        assertTrue(
            WORK_STORE !in factory.stores,
            "the account that took the lock must not have another account's list rewritten into it",
        )
        assertTrue(
            factory.stores.values.none { it.getStringOrNull(DEVICES_KEY) != null },
            "a mutation whose account changed underneath it belongs to no store",
        )
    }

    /**
     * Fired exactly once each, with no re-signal: the repository subscribes to the login events
     * when it is constructed, so there is no window in which a collector can be attached and an
     * event published into it can be lost.
     */
    @Test
    fun `observeAll follows a logout and a login as another account`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val events = InMemoryUserEventsPersistence(UnconfinedFacade)
        val devices = repository(factory, preferences, events)

        preferences.signIn("work")
        devices.add(phone, PairingOwner.current(preferences))
        preferences.signIn("ster")
        devices.add(laptop, PairingOwner.current(preferences))

        val emissions = Channel<List<TrustedDevice>>(Channel.UNLIMITED)
        val collector = launch(Dispatchers.Unconfined) { devices.observeAll().collect { emissions.send(it) } }

        assertEquals(listOf(laptop), withTimeout(TIMEOUT_MS) { emissions.receive() }, "starts on the signed-in account")

        preferences.signOut()
        events.update(UserEvent.LoginChanged(AppUser.Anonymous))
        assertEquals(
            emptyList(),
            withTimeout(TIMEOUT_MS) { emissions.receive() },
            "a live observer must follow the account switch",
        )

        preferences.signIn("work")
        events.update(UserEvent.LoginChanged(preferences.user))
        assertEquals(
            listOf(phone),
            withTimeout(TIMEOUT_MS) { emissions.receive() },
            "a live observer must follow the account switch",
        )

        collector.cancel()
    }

    /**
     * A cancelled write is not a refused one, and this repository must not answer for it.
     *
     * [LocalTrustedDevicesRepository.add] folds a failed write into `false` so a caller can tell
     * the user their pairing did not reach disk. A `CancellationException` swallowed by that fold
     * is reported as exactly that — "the device was not added" on screen because the user navigated
     * away mid-write — while the coroutine that was cancelled carries on as if it had not been.
     */
    @Test
    fun `a cancelled write propagates instead of being reported as a refused one`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val devices = repository(factory, preferences)
        factory.cancelWrites(STER_STORE)

        assertFailsWith<CancellationException> { devices.add(laptop, PairingOwner.current(preferences)) }

        assertNull(
            factory.store(STER_STORE).getStringOrNull(DEVICES_KEY),
            "precondition: the write really was interrupted",
        )
    }

    @Test
    fun `with no account signed in reads are empty and writes are dropped`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser(null)
        val devices = repository(factory, preferences)

        assertEquals(emptyList(), devices.getAll())
        assertFalse(
            devices.add(laptop, PairingOwner.current(preferences)),
            "there is no account to attribute a pairing to, and the caller is told",
        )
        devices.updateLastSync(laptop.name, laptop.lastHost, timestampMs = 1L)
        devices.markSignedHybridPairingsForReverification()
        assertEquals(emptyList(), devices.getAll(), "there is no account to attribute a pairing to")
        assertEquals(emptyList(), devices.observeAll().first(), "and the screen renders empty rather than crashing")

        assertEquals(
            setOf(LEGACY_STORE),
            factory.stores.keys,
            "only the legacy store is touched before sign-in; no account store is invented",
        )
    }

    private fun repository(
        factory: NamedStores,
        preferences: UserPreferences,
        events: UserEventPersistence = InMemoryUserEventsPersistence(UnconfinedFacade),
    ) = LocalTrustedDevicesRepository(
        encryptedFactory = factory,
        userPreferences = preferences,
        userEvents = events,
        coroutinesContextFacade = UnconfinedFacade,
    )

    /** Name-keyed stores, the way both real factories behave: one name, one backing file/node. */
    private class NamedStores : EncryptionSettingsFactory {
        val stores = mutableMapOf<String, MapSettings>()
        private val failingClears = mutableMapOf<String, Int>()
        private val cancellingWrites = mutableSetOf<String>()

        override fun createEncrypted(name: String): Settings = Guarded(name, stores.getOrPut(name) { MapSettings() })

        fun store(name: String): MapSettings = stores.getValue(name)

        fun seed(name: String, vararg devices: TrustedDevice) {
            stores.getOrPut(name) { MapSettings() }
                .putString(DEVICES_KEY, Json.encodeToString(devices.toList()))
        }

        /** Makes the next [times] `clear()` calls on [name] fail, the way a prefs node can. */
        fun failClears(name: String, times: Int) {
            failingClears[name] = times
        }

        /** Interrupts writes of the device list to [name] the way a cancelled caller does. */
        fun cancelWrites(name: String) {
            cancellingWrites += name
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

            override fun putString(key: String, value: String) {
                // The scope marker is the store's own initialisation, not the caller's write.
                if (key == DEVICES_KEY && name in cancellingWrites) throw CancellationException("write cancelled")
                delegate.putString(key, value)
            }
        }
    }

    /** The boring half of [UserPreferences]; this repository asks none of it. */
    private abstract class TestUserPreferences : UserPreferences {
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun clear() = Unit

        protected companion object {
            val CREDENTIAL = Password(hash = "hash", salt = "salt")
        }
    }

    /**
     * Who is signed in right now, with `LocalUserPreferences`' session behaviour: [clear] drops the
     * session id and the next read mints a new one, while the stored user survives it.
     */
    private class SwitchableUser(userName: String?) : TestUserPreferences() {
        var user: AppUser = userName?.let { AppUser.LoggedIn(it, CREDENTIAL) } ?: AppUser.Anonymous
            private set

        private var sessionId: String? = null
        private var minted = 0

        fun signIn(userName: String) {
            user = AppUser.LoggedIn(userName, CREDENTIAL)
        }

        fun signOut() {
            user = AppUser.Anonymous
        }

        override suspend fun getUser(): AppUser = user
        override suspend fun getSessionId(): String = sessionId ?: "session-${++minted}".also { sessionId = it }
        override suspend fun clear() {
            sessionId = null
        }
    }

    /**
     * Changes its answer part-way through an operation, so the window between an owner being
     * sampled — by the caller for [LocalTrustedDevicesRepository.add], by the operation itself for
     * the mutators that take none — and the store taking its lock can be hit deterministically: the
     * account flips after [switchAfterUserReads] reads of the user, and the session is reissued
     * after [reissueAfterSessionReads] reads of the session id.
     */
    private class RacingUser(
        private val first: String,
        private val then: String = first,
        private val switchAfterUserReads: Int = Int.MAX_VALUE,
        private val reissueAfterSessionReads: Int = Int.MAX_VALUE,
    ) : TestUserPreferences() {
        private var userReads = 0
        private var sessionReads = 0

        override suspend fun getUser(): AppUser {
            userReads++
            return AppUser.LoggedIn(if (userReads > switchAfterUserReads) then else first, CREDENTIAL)
        }

        override suspend fun getSessionId(): String {
            sessionReads++
            return if (sessionReads > reissueAfterSessionReads) "session-reissued" else "session-original"
        }
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }

    private companion object {
        const val LEGACY_STORE = "trusted_devices"
        const val STER_STORE = "trusted_devices_ster"
        const val WORK_STORE = "trusted_devices_work"
        const val DEVICES_KEY = "devices"
        const val TIMEOUT_MS = 10_000L
    }
}
