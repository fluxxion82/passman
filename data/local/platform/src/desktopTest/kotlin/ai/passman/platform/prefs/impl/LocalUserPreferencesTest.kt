package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import com.russhwolf.settings.MapSettings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import ai.passman.domain.base.CoroutinesContextFacade

/**
 * The conditional credential write. `changeUserPassword`'s rollback used to be a bare
 * read-compare-upsert, which narrows the wrong-credential-overwrite window without closing it: a
 * rival password change landing between the compare and the write is silently overwritten, and the
 * rival's keyring is then the only thing that opens a credential that no longer exists. The
 * primitive makes compare-and-write one guarded step, so within one process the window is gone.
 * (Across processes it remains advisory — `Settings` offers no CAS — which the KDoc says plainly.)
 * Suggestion-list coverage also pins pre-auth ordering and the stale-last-used guard.
 */
class LocalUserPreferencesTest {

    private val credentialA = Password(hash = "hash-a", salt = "salt-a")
    private val credentialB = Password(hash = "hash-b", salt = "salt-b")
    private val credentialC = Password(hash = "hash-c", salt = "salt-c")

    @Test
    fun `replaceCredential declines when the stored credential is not the expected one`() = runBlocking {
        val prefs = prefs()
        prefs.upsert(AppUser.LoggedIn("frank", credentialA))

        assertFalse(
            prefs.replaceCredential("frank", expected = credentialB, replacement = credentialC),
            "another change owns the stored credential; writing over it strands that change's keyring",
        )
        assertEquals(credentialA, prefs.getStoredCredentials("frank"), "a declined replace must write nothing")
    }

    @Test
    fun `replaceCredential replaces when the stored credential matches`() = runBlocking {
        val prefs = prefs()
        prefs.upsert(AppUser.LoggedIn("frank", credentialA))

        assertTrue(prefs.replaceCredential("frank", expected = credentialA, replacement = credentialB))

        assertEquals(credentialB, prefs.getStoredCredentials("frank"))
        val user = prefs.getUser()
        assertTrue(user is AppUser.LoggedIn && user.password == credentialB, "the singleton user keys follow the map")
    }

    @Test
    fun `replaceCredential for an account with no stored credential declines`() = runBlocking {
        assertFalse(prefs().replaceCredential("nobody", expected = credentialA, replacement = credentialB))
    }

    /**
     * The compare and the write are one step: of many racers all expecting the same starting
     * credential, exactly one may win. Without the guard, two can both pass the compare and both
     * report success — at which point one of them restored a credential the other just replaced.
     * Real threads (`Dispatchers.Default`), because a single-threaded dispatcher serialises the race
     * away and the test would pass no matter what the code did.
     */
    @Test
    fun `only one of many racing replaces can win`() = runBlocking {
        repeat(20) { round ->
            val prefs = prefs()
            prefs.upsert(AppUser.LoggedIn("frank", credentialA))

            val wins = coroutineScope {
                (0 until 8).map { racer ->
                    async(Dispatchers.Default) {
                        prefs.replaceCredential(
                            "frank",
                            expected = credentialA,
                            replacement = Password(hash = "hash-$round-$racer", salt = "salt"),
                        )
                    }
                }.awaitAll()
            }

            assertEquals(1, wins.count { it }, "round $round: the compare and the write must be indivisible")
        }
    }

    @Test
    fun `known usernames are empty when no credentials are stored`() = runBlocking {
        assertEquals(emptyList(), prefs().getKnownUsernames())
    }

    @Test
    fun `known usernames contains a single stored credential`() = runBlocking {
        val prefs = prefs()
        prefs.upsert(AppUser.LoggedIn("ada", credentialA))

        assertEquals(listOf("ada"), prefs.getKnownUsernames())
    }

    @Test
    fun `known usernames puts the last used account before the remaining alphabetical accounts`() = runBlocking {
        val prefs = prefs()
        prefs.upsert(AppUser.LoggedIn("zoe", credentialC))
        prefs.upsert(AppUser.LoggedIn("ada", credentialA))
        prefs.upsert(AppUser.LoggedIn("mia", credentialB))
        prefs.upsert(AppUser.LoggedIn("ada", credentialA))

        assertEquals(listOf("ada", "mia", "zoe"), prefs.getKnownUsernames())
    }

    @Test
    fun `known usernames sorts remaining accounts case insensitively`() = runBlocking {
        val prefs = prefs()
        prefs.upsert(AppUser.LoggedIn("Bob", credentialB))
        prefs.upsert(AppUser.LoggedIn("ada", credentialA))
        prefs.upsert(AppUser.LoggedIn("zoe", credentialC))

        assertEquals(listOf("zoe", "ada", "Bob"), prefs.getKnownUsernames())
    }

    @Test
    fun `known usernames omits a stale last used account`() = runBlocking {
        val settings = MapSettings().apply {
            putString("user_name", "ghost")
            putString(
                "stored_v2",
                Json { allowStructuredMapKeys = true; ignoreUnknownKeys = true }.encodeToString(
                    mapOf("zoe" to credentialC, "ada" to credentialA),
                ),
            )
        }

        assertEquals(listOf("ada", "zoe"), prefs(settings).getKnownUsernames())
    }

    @Test
    fun `known usernames includes legacy pair map credentials`() = runBlocking {
        val settings = MapSettings().apply {
            putString(
                "stored",
                Json { allowStructuredMapKeys = true; ignoreUnknownKeys = true }.encodeToString(
                    mapOf(
                        "zoe" to ("hash-z" to "salt-z"),
                        "ada" to ("hash-a" to "salt-a"),
                    ),
                ),
            )
        }

        assertEquals(listOf("ada", "zoe"), prefs(settings).getKnownUsernames())
    }

    private fun prefs(settings: MapSettings = MapSettings()) = LocalUserPreferences(
        encryptedFactory = object : EncryptionSettingsFactory {
            override fun createEncrypted(name: String) = settings
        },
        coroutinesContextFacade = UnconfinedFacade,
    )

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
