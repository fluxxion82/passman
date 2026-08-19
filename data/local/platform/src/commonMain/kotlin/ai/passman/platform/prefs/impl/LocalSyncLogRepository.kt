package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.Settings
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

/**
 * This device's sync activity log, stored **per account** — the same reason
 * [LocalTrustedDevicesRepository] scopes trusted-device pairings per account: sync only ever runs
 * for the signed-in account's vault, so a log entry belongs to that account and nobody else's, the
 * same way a pairing does.
 *
 * ## This log is never synced
 *
 * `DirectoryBundler.bundle` — the only thing that turns a local directory into wire bytes — is
 * called on exactly `pgp/<user>/` and `keystore/<user>/`; the password vault crosses the wire as a
 * database file at its own call site, never as a bundled directory. This store is neither of
 * those: it is its own encrypted `Settings` node (`sync_log_<account>`), a preferences transport
 * `DirectoryBundler` never touches — and `DirectoryBundler.syncExclusions` could not name it even
 * if it needed to, since that set matches exact basenames *inside* a directory being bundled, and
 * a preferences node is not a file inside anything `DirectoryBundler` ever walks. **What would
 * actually put this log at risk**: relocating it out of `Settings` into a file under the app's
 * data directory, or adding any whole-profile export path. Either would give the log a way off
 * this device outside the push/pull transports `DirectoryBundler` guards, and that is the point
 * this store's entries would need folding into whatever filter guards that new door — the same
 * way `JvmPasswordDatabaseStorage` flags `.premigration.v2` as needing an exclusion before
 * `database/` could ever be bundled.
 *
 * ## Why this does not need [LocalTrustedDevicesRepository]'s session-race guard
 *
 * That repository compares the account *and* the session under its write lock because its entries
 * are the mTLS SPKI pin and PQ public keys of a paired peer — material one account attested to
 * that must never land in another account's store, even across a login that races the write. A
 * sync log entry carries no such material: [SyncLogEntry.host] and [SyncLogEntry.deviceName] are
 * a network address and a display name, not credentials or key material, and [SyncLogEntry.detail]
 * is deliberately restricted to a friendly failure string (see [SyncLogEntry]'s KDoc). The worst a
 * lost account-switch race can do here is misfile a history row under the wrong account's log —
 * account B would see a peer name from account A's session, a row B's own paired-devices UI never
 * shows, since that UI only ever lists B's own pairings. But that peer name was never confidential
 * to begin with, just momentarily misattributed: nothing about seeing it grants B any capability A
 * had. That is a display inconvenience, not the security compromise the session check exists to
 * prevent — so a plain per-call account resolution under [mutex] is enough;
 * [PairingOwner][ai.passman.domain.connectivity.PairingOwner]'s extra bookkeeping would be solving
 * a problem this store does not have.
 *
 * Recording is meant to never fail a sync (`RecordSyncOutcome` guarantees that at the call site),
 * so failures here are handled the same way [LocalTrustedDevicesRepository]'s reads are: logged
 * and answered with an empty result or a silent no-op, never thrown past this class for a routine
 * storage hiccup — store opening included, via [openAccountStore], which wraps `createEncrypted`
 * the same way [LocalTrustedDevicesRepository.openAccountStore] does rather than letting it throw
 * straight out of the platform factory (desktop's `createEncrypted` does exactly that when there
 * is no secure credential store to hold the master key). [append]'s read-modify-write is the one
 * exception: an undecodable stored blob is refused rather than silently discarded, so a corrupt
 * read costs one lost entry instead of every record the store already held — see
 * [loadAllForMutation].
 */
class LocalSyncLogRepository(
    private val encryptedFactory: EncryptionSettingsFactory,
    private val userPreferences: UserPreferences,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : SyncLogRepository {
    private val format = Json { ignoreUnknownKeys = true }

    /** Serialises account resolution and the read-modify-write together, same as reads below. */
    private val mutex = Mutex()
    private val stores = mutableMapOf<String, Settings>()

    override suspend fun append(entry: SyncLogEntry): Unit = withContext(coroutinesContextFacade.io) {
        mutex.withLock {
            val store = currentAccountStore() ?: return@withContext
            // Sorted newest-first on every write, not just kept in append order: two sync sessions
            // (say, passwords and PGP keys) can finish close enough together that their recordings
            // land out of `at` order, and the cap below has to drop the oldest *by timestamp*, not
            // the one that happened to be appended first.
            //
            // loadAllForMutation, not loadAll: a decode failure here must not be swallowed into
            // emptyList() the way a read is allowed to be, or this write would silently replace up
            // to MAX_ENTRIES history rows with the one entry being appended.
            val trimmed = (loadAllForMutation(store) + entry).sortedByDescending { it.at }.take(MAX_ENTRIES)
            save(store, trimmed)
        }
    }

    override suspend fun recent(): List<SyncLogEntry> = withContext(coroutinesContextFacade.io) {
        mutex.withLock {
            val store = currentAccountStore() ?: return@withContext emptyList()
            // Sorted again on read, defensively: correctness here must not depend on every writer
            // having sorted on the way in.
            loadAll(store).sortedByDescending { it.at }
        }
    }

    override suspend fun clear(): Unit = withContext(coroutinesContextFacade.io) {
        mutex.withLock {
            val store = currentAccountStore() ?: return@withContext
            save(store, emptyList())
        }
    }

    /** The signed-in account's log store, or null when nobody is signed in. Opened once, cached. */
    private suspend fun currentAccountStore(): Settings? {
        val userName = when (val user = userPreferences.getUser()) {
            is AppUser.LoggedIn -> user.userName
            is AppUser.AccountCreated -> user.userName
            AppUser.Anonymous -> null
        } ?: return null
        return stores[userName] ?: openAccountStore(userName)?.also { stores[userName] = it }
    }

    /**
     * Opens (and on first touch, wipes) [userName]'s log store, or null if it could not be opened.
     *
     * Wrapped in [runCatching] because [EncryptionSettingsFactory.createEncrypted] is not
     * guaranteed to succeed: desktop's implementation throws outright when there is no secure
     * credential store to hold the master key protecting the node
     * (`DesktopEncryptionSettingsFactory.loadOrCreateMasterKey`), and letting that escape here
     * would hand [SyncActivityViewModel] an exception it carries no catch for, over a feature
     * ([RecordSyncOutcome]) whose entire contract with its callers is "never fail on my account."
     *
     * The wipe-then-stamp mirrors [LocalTrustedDevicesRepository.openAccountStore] for the same
     * root cause: `DesktopEncryptionSettingsFactory.createEncrypted` seeds any brand-new, still
     * *empty* node from the pre-per-store-node flat prefs node it replaced, so on a legacy desktop
     * install the first open of `sync_log_<user>` would otherwise silently copy every encrypted
     * entry that flat node ever held — login credentials, the old device-global trusted-device
     * list, whatever else once lived flat — into a store that has nothing to do with any of it.
     * Nothing collides (same master key, unrelated key names) and nothing breaks, but that stale
     * ciphertext would then sit in this node forever, because [clear] only ever empties the *log*
     * key, never the whole node. A freshly created per-account node has no legitimate content
     * before its first touch, so wiping it before stamping the marker costs nothing real; a
     * stamped store is never empty again, which is what stops the reseed from repeating on a later
     * launch. Fails closed: if the wipe or the stamp does not both go through, the store may still
     * be holding that seeded ciphertext, so it is neither returned nor cached, and the next call
     * retries.
     */
    private fun openAccountStore(userName: String): Settings? = runCatching {
        val store = encryptedFactory.createEncrypted(storeNameFor(userName))
        if (store.getStringOrNull(SCOPE_MARKER) == null) {
            store.clear()
            store.putString(SCOPE_MARKER, SCOPE_MARKER_VALUE)
        }
        store
    }.getOrElse {
        KLogger.e(it) { "could not initialise the sync activity log store; refusing to use it" }
        null
    }

    private fun loadAll(store: Settings): List<SyncLogEntry> {
        val raw = store.getStringOrNull(LOG_KEY) ?: return emptyList()
        return runCatching { format.decodeFromString<List<SyncLogEntry>>(raw) }.getOrElse {
            KLogger.e(it) { "sync activity log is unreadable; returning an empty display list" }
            emptyList()
        }
    }

    /**
     * Same read as [loadAll], but for [append]'s read-modify-write, where swallowing a decode
     * failure into `emptyList()` would be actively destructive: the write that follows would
     * replace whatever the store actually held — up to [MAX_ENTRIES] history rows — with a list
     * containing only the one new entry. Throwing instead costs one lost entry (`RecordSyncOutcome`
     * already treats any append failure as "log it and move on," never the sync's own outcome)
     * rather than the user's whole history — the same trade
     * [LocalTrustedDevicesRepository.loadAllForMutation] makes for the same reason. [recent] keeps
     * swallowing via [loadAll] because a *read* degrading to empty costs nothing the write path
     * doesn't already risk losing anyway.
     */
    private fun loadAllForMutation(store: Settings): List<SyncLogEntry> {
        val raw = store.getStringOrNull(LOG_KEY) ?: return emptyList()
        return try {
            format.decodeFromString(raw)
        } catch (error: Throwable) {
            KLogger.e(error) { "sync activity log is unreadable; refusing to overwrite it with just the new entry" }
            throw error
        }
    }

    private fun save(store: Settings, entries: List<SyncLogEntry>) {
        store.putString(LOG_KEY, format.encodeToString(entries))
    }

    private companion object {
        const val PREFS_NAME = "sync_log"
        const val LOG_KEY = "entries"

        /**
         * Present exactly when [openAccountStore] has already wiped this account's store of
         * whatever `DesktopEncryptionSettingsFactory`'s legacy-flat-node seeding may have put
         * there. Never a user value; a separate marker from
         * [LocalTrustedDevicesRepository]'s `SCOPE_MARKER` because the two guard different nodes
         * and have no reason to share a name.
         */
        const val SCOPE_MARKER = "__passman_sync_log_scoped__"
        const val SCOPE_MARKER_VALUE = "1"

        /**
         * 100 records, newest kept, trimmed on [append]. Comfortably inside desktop's chunked-value
         * headroom (`DesktopEncryptionSettingsFactory` splits any value past `java.util.prefs`' 8192
         * character cap transparently), so the cap is about not letting the log grow forever, not
         * about working around that limit.
         */
        const val MAX_ENTRIES = 100

        /**
         * `<PREFS_NAME>_<account>`, escaped into `[A-Za-z0-9._-]` the same reversible way
         * [LocalTrustedDevicesRepository]'s `storeNameFor` does — not shared code, because the two
         * escape the same characters for two independent reasons, but a store-name collision
         * between two accounts would be exactly the same bug either place it happened.
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
