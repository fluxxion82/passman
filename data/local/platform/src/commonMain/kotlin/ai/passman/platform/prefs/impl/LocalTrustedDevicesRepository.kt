package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.Settings
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

/**
 * Trusted device pairings, stored **per account**.
 *
 * A pairing is not device-global data: the peer's bundle is pinned to the identity in
 * `keystore/<user>/`, so an entry paired while account A was signed in can never authenticate for
 * account B. Storing them in one device-wide file therefore did two wrong things at once — it
 * showed one account the other's device names, hosts and sync times, and it offered account B
 * entries that were already functionally dead for it. Each account now gets its own encrypted
 * store, `trusted_devices_<account>`.
 *
 * The account is resolved **per call**, never captured at construction: this repository is a
 * process-wide singleton built before the first login, and a user can log out and sign in as a
 * different account without restarting.
 *
 * ### What counts as signed in
 *
 * Not [UserPreferences.getUser] on its own. `LocalUserPreferences` keeps `USER_NAME` after a
 * logout — that is what lets the login screen prefill the last account — so `getUser()` answers
 * with account A long after A logged out, and this store gates sync: its entries are the mTLS SPKI
 * pins and PQ keys the receive-side authorizer matches against. A data server still running after
 * the logout would keep admitting A's paired peers.
 *
 * So the account comes from what [UserEvent.LoginChanged] last announced, which is the one thing a
 * logout does reset: [ai.passman.domain.user.LogoutUser] publishes
 * `LoginChanged(Anonymous)` as its first act, and only a completed login or signup publishes a
 * signed-in user again. Before the first event — this singleton can be built after the login that
 * would have told it — it falls back to `getUser()`, which is the pre-login state where no session
 * keys exist and no server is listening; from the first event onwards the announcements are
 * authoritative and a logout fails every read and write closed.
 *
 * ### Mutations are bound to the account *and* the session
 *
 * Every write resolves its account *under* [mutex], so an account switch racing the write can never
 * split the read-modify-write across two stores, and holds that resolution against an expected
 * owner — both halves of it, the account name and the session id, never either alone. Each half
 * catches a different switch. A session change is what
 * [ai.passman.domain.user.LogoutUser] does through [UserPreferences.clear], so a session
 * mismatch means a logout interleaved with this operation. A name change with the session intact is
 * the login that never logged the previous account out, and it is the dangerous one: the write is
 * carrying an mTLS pin and PQ keys that only account A ever attested to, and committing it under B
 * grants B trust in A's peer. Either mismatch drops the write, loudly.
 *
 * Where that expected owner comes from is the whole difference between a guard and a formality.
 * [add] takes it from its caller — the account the peer material was attested to under, decided
 * before any of the work leading up to the write — so the comparison under the lock is between the
 * material's owner and the account about to be written to. The mutators that carry no such claim
 * ([remove], [updateLastSync], [updateHost], [updateAllowedOps],
 * [markSignedHybridPairingsForReverification])
 * sample the account they entered with instead; they rewrite entries already filed under an
 * account rather than importing a peer's keys into one, so the narrower window is theirs to cover.
 * Two self-samples can only ever catch a switch that lands between them — a caller that checked the
 * account, then read [getAll], then called [add] would leave exactly the gap where a `LoginUser`
 * with no logout flips the account while both the caller and this store see two matching samples
 * on their own side of it.
 *
 * With no account signed in, every read is empty and every write is dropped rather than crashing;
 * pairing and sync are post-login surfaces, but the singleton itself exists before login.
 *
 * A dropped write is also a *reported* one: [add] answers `false` so its caller cannot show the
 * user a pairing that never reached disk while the peer already trusts them.
 */
class LocalTrustedDevicesRepository(
    private val encryptedFactory: EncryptionSettingsFactory,
    private val userPreferences: UserPreferences,
    userEvents: UserEventPersistence,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : TrustedDevicesRepository {
    private val format = Json { ignoreUnknownKeys = true }

    /** Bumped on every write and every login/logout so a live [observeAll] re-reads. */
    private val revisions = MutableStateFlow(0L)

    /** Serialises a mutation's account resolution and its read-modify-write halves. */
    private val mutex = Mutex()

    /** Guards [stores] and the one-shot purge of the pre-account-scoping global store. */
    private val storesMutex = Mutex()
    private val stores = mutableMapOf<String, Settings>()
    private var legacyPurged = false

    /**
     * The user the login events last announced, or null while they have announced nothing to this
     * instance yet. Only ever written by [loginWatch].
     */
    private val announced = MutableStateFlow<AppUser?>(null)

    private val loginWatch = CoroutineScope(coroutinesContextFacade.default + SupervisorJob())

    init {
        // Undispatched on purpose: the subscription is registered on the constructing thread before
        // the constructor returns, so a login or logout published straight afterwards cannot fall
        // into a gap between "this repository exists" and "this repository is listening". The same
        // property is what lets [observeAll] hand new collectors a value with no re-signal needed.
        loginWatch.launch(start = CoroutineStart.UNDISPATCHED) {
            userEvents.events()
                .filterIsInstance<UserEvent.LoginChanged>()
                .collect { event ->
                    announced.value = event.user
                    revisions.update { it + 1 }
                }
        }
    }

    override fun observeAll(): Flow<List<TrustedDevice>> =
        revisions.map { getAll() }.distinctUntilChanged()

    override suspend fun getAll(): List<TrustedDevice> = withContext(coroutinesContextFacade.io) {
        readableStore()?.let(::loadAll).orEmpty()
    }

    /**
     * One match, or nothing — never a first match.
     *
     * Two records really can claim one address: [add] dedupes on [TrustedDevice.name], [updateHost]
     * repoints on name with no collision check, and re-pairing the same physical peer under a new
     * name produces a second record holding the same `lastHost` *and* the same fingerprint. A
     * `firstOrNull` here answered one of them arbitrarily, and every caller that trusted the answer
     * — the last-sync stamp, the mTLS SPKI pin, the sync log's device name — could then act on a
     * pairing the user never chose. Those callers now carry the chosen [TrustedDevice] instead, and
     * what is left for this method is resolving a *typed* address, where there is no chosen record
     * and an ambiguous answer is worse than none: pinning one of two indistinguishable pairings
     * would fail the handshake for reasons the user cannot see. Refusing lets the caller say the
     * address does not identify one paired device.
     */
    override suspend fun getByHost(host: String): TrustedDevice? = withContext(coroutinesContextFacade.io) {
        val matches = readableStore()?.let(::loadAll)?.filter { it.lastHost == host }.orEmpty()
        if (matches.size > 1) {
            // The host is not logged: this line goes to a log the peer material must not reach.
            KLogger.w {
                "${matches.size} paired devices claim the same address; refusing to resolve it to one " +
                    "of them - pick the device explicitly instead"
            }
            return@withContext null
        }
        matches.singleOrNull()
    }

    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean =
        mutate("add ${device.name}", expectedOwner) { devices ->
            devices.filterNot { it.name == device.name } + device
        }

    override suspend fun remove(name: String) {
        mutate("remove $name") { devices -> devices.filter { it.name != name } }
    }

    override suspend fun updateLastSync(
        name: String,
        host: String,
        timestampMs: Long,
    ) {
        mutate("updateLastSync $name") { devices ->
            devices.map { if (it.name == name) it.copy(lastHost = host, lastSyncedAt = timestampMs) else it }
        }
    }

    override suspend fun updateHost(name: String, host: String) {
        mutate("updateHost $name") { devices ->
            devices.map { if (it.name == name) it.copy(lastHost = host) else it }
        }
    }

    override suspend fun updateAllowedOps(
        name: String,
        allowedOps: Set<String>,
    ) {
        mutate("updateAllowedOps $name") { devices ->
            devices.map { if (it.name == name) it.copy(allowedOps = allowedOps) else it }
        }
    }

    override suspend fun markSignedHybridPairingsForReverification() {
        mutate("markSignedHybridPairingsForReverification") { devices ->
            devices.map { device ->
                if (device.pairingSecurity == PairingSecurity.SignedHybridRequired) {
                    device.copy(pairingSecurity = PairingSecurity.AwaitingConfirmation)
                } else {
                    device
                }
            }
        }
    }

    /**
     * Applies [transform] to [expectedOwner]'s list, under one lock.
     *
     * The account resolved *inside* the lock is the one whose store is opened and written, and it
     * has to be the same account, in the same session, as [expectedOwner] — both halves, not
     * either. The session id alone is not enough: it is reissued by a logout, so it catches "A
     * logged out and B logged in", but an account switch that reuses the session (a `LoginUser`
     * with no interleaved logout) leaves it unchanged, and the write would then commit peer
     * material gathered as A into B's store — handing B trust in a device only A ever attested to.
     * The account name alone is not enough either: A can log out and back in, and a write that
     * started before that logout has provenance in a login that no longer exists.
     *
     * A null [expectedOwner] means the caller made no claim about whose material this is, so the
     * account signed in at entry is taken as the claim. That covers the switch that lands between
     * entry and the lock and nothing earlier, which is all the ownerless mutators need: they edit
     * rows that are already this account's. It is not enough for [add], and [add] does not use it.
     *
     * A write with no account, one whose owner or session is not [expectedOwner]'s, one whose store
     * will not initialise, and one whose store cannot be read or written is dropped with a log
     * rather than landing anywhere, and reports `false` so a caller cannot tell the user it was
     * saved. Cancellation is not one of those: it belongs to the caller and propagates untouched.
     */
    private suspend fun mutate(
        operation: String,
        expectedOwner: PairingOwner? = null,
        transform: (List<TrustedDevice>) -> List<TrustedDevice>,
    ): Boolean = withContext(coroutinesContextFacade.io) {
        val expected = expectedOwner ?: currentOwner() ?: return@withContext dropped(operation)
        mutex.withLock {
            val owner = currentOwner() ?: return@withContext dropped(operation)
            if (owner != expected) return@withContext staleOwner(operation, expected, owner)
            // [currentOwner] never answers with a signed-in owner that has no account name; if that
            // ever changes, there is no account to file this under and the write is not ours to
            // place. Fail closed rather than reach for a store name that is not there.
            val account = owner.account ?: return@withContext dropped(operation)
            val store = accountStore(account) ?: return@withContext uninitialised(operation)
            runCatching { save(store, transform(loadAllForMutation(store))) }
                .fold(
                    onSuccess = { true },
                    onFailure = {
                        // A cancelled caller has not had its write refused, and reporting it as one
                        // would have the screen tell the user the pairing was not saved because
                        // they navigated away. Cancellation is not this repository's to answer.
                        if (it is CancellationException) throw it
                        unwritable(operation, it)
                    },
                )
        }
    }

    /**
     * The encrypted store to read from: the signed-in account's, or null when there is no account
     * or its store could not be initialised. One account resolution per call, taken under the same
     * lock that opens the store.
     *
     * Also the point where the legacy device-global store is dropped — first access of any kind,
     * whether or not anyone is signed in.
     */
    private suspend fun readableStore(): Settings? = storesMutex.withLock {
        purgeLegacyGlobalStore()
        currentOwner()?.account?.let { openOrCached(it) }
    }

    private suspend fun accountStore(userName: String): Settings? = storesMutex.withLock {
        purgeLegacyGlobalStore()
        openOrCached(userName)
    }

    private fun openOrCached(userName: String): Settings? =
        stores[userName] ?: openAccountStore(userName)?.also { stores[userName] = it }

    /**
     * Who is signed in right now, and the session that answer belongs to, or null when nobody is.
     *
     * The same [PairingOwner] the callers of [add] stamp their material with, so the comparison
     * under [mutex] is between two values of one type rather than two parallel notions of "the
     * account" that could drift apart. Nobody-signed-in is the null here rather than
     * [PairingOwner.account] being null: the session id is not read at all in that case, and a
     * resolved owner always names an account.
     */
    private suspend fun currentOwner(): PairingOwner? {
        val user = announced.value ?: userPreferences.getUser()
        val name = when (user) {
            is AppUser.LoggedIn -> user.userName
            is AppUser.AccountCreated -> user.userName
            AppUser.Anonymous -> return null
        }
        return PairingOwner(account = name, session = userPreferences.getSessionId())
    }

    /**
     * Opens (and on first touch, wipes) one account's store, or returns null if it cannot.
     *
     * A per-account store cannot legitimately hold anything before its first touch — they are new
     * with account scoping — but `DesktopEncryptionSettingsFactory` seeds any *empty* node it
     * creates from the pre-per-store-node flat prefs node, which still holds the device-global
     * device list this change exists to drop. So: wipe, then stamp. A stamped store is never empty
     * again, which is also what stops that seeding from re-running against it on a later launch.
     *
     * Fails closed: if the wipe or the stamp does not go through, the store may still be holding
     * that seeded legacy list, so it is neither returned nor cached. The caller sees no store — an
     * empty list, or a dropped write — and the next call retries the initialisation.
     */
    private fun openAccountStore(userName: String): Settings? = runCatching {
        val store = encryptedFactory.createEncrypted(storeNameFor(userName))
        if (store.getStringOrNull(SCOPE_MARKER) == null) {
            store.clear()
            store.putString(SCOPE_MARKER, SCOPE_MARKER_VALUE)
        }
        store
    }.getOrElse {
        KLogger.e(it) { "could not initialise the per-account trusted device store; refusing to use it" }
        null
    }

    /**
     * Drops the pre-account-scoping global store, once.
     *
     * No attribution guessing: every entry in it was pinned to whichever account happened to be
     * signed in when it was paired, and nothing on disk records which. Leaving it would keep the
     * leaked device names, hosts and sync times readable, so it is cleared outright and the user
     * re-pairs. Once per process and unconditional: clearing an already-empty store costs nothing,
     * and both platform factories can re-materialise this store's contents behind our back on a
     * later launch (desktop re-seeds an emptied node from the legacy flat prefs node, Android
     * retries an EncryptedSharedPreferences migration that previously failed). The marker left
     * behind is what stops the desktop half of that.
     *
     * Marked done only once the clear and the stamp have both succeeded, so a transient failure
     * costs one retry rather than leaving the leaked list readable for the rest of the process.
     */
    private fun purgeLegacyGlobalStore() {
        if (legacyPurged) return
        runCatching {
            val legacy = encryptedFactory.createEncrypted(PREFS_NAME)
            legacy.clear()
            legacy.putString(SCOPE_MARKER, SCOPE_MARKER_VALUE)
        }.onSuccess {
            legacyPurged = true
            KLogger.d { "dropped the pre-account-scoping trusted device store; devices must be re-paired" }
        }.onFailure {
            KLogger.e(it) { "could not drop the legacy device-global trusted device store; retrying on next access" }
        }
    }

    private fun dropped(operation: String): Boolean {
        KLogger.w { "no account is signed in; dropping trusted device $operation" }
        return false
    }

    /** Never logs either account name: this line goes to a log the peer material must not reach. */
    private fun staleOwner(operation: String, expected: PairingOwner, current: PairingOwner): Boolean {
        val what = if (expected.account == current.account) "the session was reissued" else "the account changed"
        KLogger.w { "$what mid-operation; dropping trusted device $operation" }
        return false
    }

    private fun uninitialised(operation: String): Boolean {
        KLogger.w { "the account's trusted device store is not initialised; dropping $operation" }
        return false
    }

    private fun unwritable(operation: String, cause: Throwable): Boolean {
        KLogger.e(cause) { "the account's trusted device store could not be updated; dropping $operation" }
        return false
    }

    private fun loadAll(store: Settings): List<TrustedDevice> {
        val raw = store.getStringOrNull(DEVICES_KEY) ?: return emptyList()
        return runCatching { format.decodeFromString<List<TrustedDevice>>(raw) }.getOrElse {
            KLogger.e(it) { "trusted devices store is unreadable; returning an empty display list" }
            emptyList()
        }
    }

    private fun loadAllForMutation(store: Settings): List<TrustedDevice> {
        val raw = store.getStringOrNull(DEVICES_KEY) ?: return emptyList()
        return try {
            format.decodeFromString(raw)
        } catch (error: Throwable) {
            KLogger.e(error) { "trusted devices store is unreadable; refusing to overwrite it" }
            throw error
        }
    }

    private fun save(store: Settings, devices: List<TrustedDevice>) {
        store.putString(DEVICES_KEY, format.encodeToString(devices))
        revisions.update { it + 1 }
    }

    private companion object {
        const val PREFS_NAME = "trusted_devices"
        const val DEVICES_KEY = "devices"

        /** Present exactly when a store has been through account scoping. Never a user value. */
        const val SCOPE_MARKER = "__passman_account_scoped__"
        const val SCOPE_MARKER_VALUE = "1"

        /**
         * `<PREFS_NAME>_<account>`, with the account escaped into `[A-Za-z0-9._-]`.
         *
         * The escape is reversible rather than lossy (`_` doubles, anything else becomes
         * `_u<code>_`) so that two accounts can never be folded onto one store name — that
         * collision is the exact class of bug per-account scoping is fixing. The name has to
         * survive being a Java Preferences node on desktop and a SharedPreferences file name on
         * Android, and both platforms' factories take it verbatim apart from their own sanitising.
         */
        fun storeNameFor(userName: String): String = buildString {
            append(PREFS_NAME)
            append('_')
            for (ch in userName) {
                when {
                    ch in 'a'..'z' || ch in 'A'..'Z' || ch in '0'..'9' || ch == '.' || ch == '-' -> append(ch)
                    ch == '_' -> append("__")
                    else -> append("_u").append(ch.code).append('_')
                }
            }
        }
    }
}
