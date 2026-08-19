package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import com.russhwolf.settings.MapSettings
import com.russhwolf.settings.Settings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json

/**
 * The two storage-level obligations that don't belong at the domain layer: the 100-record cap
 * (obligation 5) and newest-first ordering regardless of how entries were appended (obligation 6).
 * Plus the account scoping this store adds on top of [SyncLogRepository][ai.passman.domain.settings.repository.SyncLogRepository]'s
 * plain contract — see this class's own KDoc for why per-account scoping is right here without
 * [LocalTrustedDevicesRepository]'s session-race guard.
 */
class LocalSyncLogRepositoryTest {

    @Test
    fun `the cap holds at 100 and keeps the newest entries`() = runBlocking {
        val factory = NamedStores()
        val repo = repository(factory, SwitchableUser("ster"))

        for (i in 1..101) repo.append(entry(at = i.toLong()))

        val recent = repo.recent()
        assertEquals(100, recent.size, "the cap must hold at 100")
        assertEquals(101L, recent.first().at, "the newest entry must survive the trim")
        assertEquals(2L, recent.last().at, "only the single oldest entry (at=1) may be dropped")
    }

    /**
     * Distinguishes "trimmed on append" from "trimmed on read" by inspecting the persisted JSON
     * directly, never calling [ai.passman.platform.prefs.impl.LocalSyncLogRepository.recent] — a
     * store that deferred trimming to the read side would still pass the test above but would fail
     * this one, because the raw record it wrote would still hold all 150 entries.
     */
    @Test
    fun `the stored record itself never exceeds the cap, proving the trim happens on append`() = runBlocking {
        val factory = NamedStores()
        val repo = repository(factory, SwitchableUser("ster"))

        repeat(150) { i -> repo.append(entry(at = (i + 1).toLong())) }

        val raw = factory.store("sync_log_ster").getStringOrNull(LOG_KEY)
        val storedCount = Json.decodeFromString<List<SyncLogEntry>>(raw!!).size
        assertEquals(100, storedCount, "the persisted record must never exceed the cap")
    }

    @Test
    fun `recent returns newest first regardless of insertion order`() = runBlocking {
        val factory = NamedStores()
        val repo = repository(factory, SwitchableUser("ster"))

        repo.append(entry(at = 100L))
        repo.append(entry(at = 50L))
        repo.append(entry(at = 200L))
        repo.append(entry(at = 75L))

        assertEquals(listOf(200L, 100L, 75L, 50L), repo.recent().map { it.at })
    }

    @Test
    fun `each account keeps its own log`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val repo = repository(factory, preferences)

        repo.append(entry(at = 1L, host = "ster-host"))
        preferences.signIn("work")
        assertEquals(emptyList(), repo.recent(), "a different account must not see the first account's log")

        repo.append(entry(at = 2L, host = "work-host"))
        preferences.signIn("ster")
        assertEquals(listOf("ster-host"), repo.recent().map { it.host }, "switching back finds the account's own log")
    }

    @Test
    fun `clear drops only the signed-in account's log`() = runBlocking {
        val factory = NamedStores()
        val preferences = SwitchableUser("ster")
        val repo = repository(factory, preferences)
        repo.append(entry(at = 1L))
        preferences.signIn("work")
        repo.append(entry(at = 2L))
        preferences.signIn("ster")

        repo.clear()

        assertEquals(emptyList(), repo.recent())
        preferences.signIn("work")
        assertEquals(1, repo.recent().size, "clearing one account's log must not touch another's")
    }

    @Test
    fun `with no account signed in reads are empty and writes are dropped`() = runBlocking {
        val factory = NamedStores()
        val repo = repository(factory, SwitchableUser(null))

        repo.append(entry(at = 1L))

        assertEquals(emptyList(), repo.recent())
        assertEquals(emptySet(), factory.stores.keys, "no account store may be invented with nobody signed in")
    }

    @Test
    fun `an unreadable stored record is treated as empty on read, but append refuses to overwrite it`() = runBlocking {
        val factory = NamedStores()
        val repo = repository(factory, SwitchableUser("ster"))
        // A real append first, so the store is past its first-touch wipe (see
        // LocalSyncLogRepository.openAccountStore) before it gets corrupted below — corrupting it
        // any earlier would just get wiped by that first-touch initialisation, and this test would
        // prove nothing about decode-failure handling.
        repo.append(entry(at = 1L))
        factory.store("sync_log_ster").putString(LOG_KEY, "not json")

        assertEquals(emptyList(), repo.recent(), "a read must still degrade to an empty display list")

        assertFailsWith<SerializationException>("append must refuse to write over an undecodable blob") {
            repo.append(entry(at = 2L))
        }
        assertEquals(
            "not json",
            factory.store("sync_log_ster").getStringOrNull(LOG_KEY),
            "a failed append must leave the corrupt blob untouched rather than replacing it",
        )
    }

    private fun entry(at: Long, host: String = "192.0.2.1") = SyncLogEntry(
        at = at,
        artifact = "passwords",
        host = host,
        outcome = SyncLogEntry.OUTCOME_SUCCESS,
    )

    private fun repository(factory: NamedStores, preferences: UserPreferences) = LocalSyncLogRepository(
        encryptedFactory = factory,
        userPreferences = preferences,
        coroutinesContextFacade = UnconfinedFacade,
    )

    /** Name-keyed stores, the way both real factories behave: one name, one backing file/node. */
    private class NamedStores : EncryptionSettingsFactory {
        val stores = mutableMapOf<String, MapSettings>()
        override fun createEncrypted(name: String): Settings = stores.getOrPut(name) { MapSettings() }
        fun store(name: String): MapSettings = stores.getValue(name)
    }

    private abstract class TestUserPreferences : UserPreferences {
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "session"
        override suspend fun clear() = Unit

        protected companion object {
            val CREDENTIAL = Password(hash = "hash", salt = "salt")
        }
    }

    private class SwitchableUser(userName: String?) : TestUserPreferences() {
        private var user: AppUser = userName?.let { AppUser.LoggedIn(it, CREDENTIAL) } ?: AppUser.Anonymous

        fun signIn(userName: String) {
            user = AppUser.LoggedIn(userName, CREDENTIAL)
        }

        override suspend fun getUser(): AppUser = user
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }

    private companion object {
        const val LOG_KEY = "entries"
    }
}
