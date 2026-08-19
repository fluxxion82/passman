package ai.passman.platform.repository

import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.repo.Platform
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/**
 * What a single mutation *reports*, and what the add path tolerates in the ordinals it reads.
 *
 * The repository's conditional-publish loop already knew whether a write landed — `mutateVault`
 * returns exactly that — but the public methods discarded it, so a save that exhausted its three
 * retries was indistinguishable from one that landed. `e6a9c82` introduced that gap: before the
 * conditional publish, writes were unconditional and effectively always landed, so there was nothing
 * to report. Now there is, and this file pins that the answer reaches the caller.
 *
 * The second half covers the two ordinal bugs recorded against the add path: `maxOf { it.id.toInt() }`
 * threw outside every `runCatching` on a non-numeric id, and `sortedBy { it.id }` was a *string* sort,
 * which files ordinal 10 between 1 and 2.
 *
 * Deliberately varied against the sibling suites: a different user (`carol`), no RSA identity in the
 * Koin scope at all — every vault here is born suite 5, so a test that strays onto the legacy path
 * fails loudly on the missing definition instead of quietly exercising it.
 *
 * No `kotlin.test.assertFails`: it catches `Throwable`, so an `OutOfMemoryError` reads as a pass.
 */
class WriteOutcomeTest {

    private lateinit var root: File
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var vaultCipher: VaultCipher
    private lateinit var prefs: FakePreferences
    private lateinit var sessionKey: VaultSessionKey

    private val user = "carol"
    private val identity = PasswordEntryIdentity(JvmSha256Service())

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("write-outcome").toFile()
        storage = JvmPasswordDatabaseStorage(object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        })
        vaultCipher = PasswordVaultCipher()
        prefs = FakePreferences()

        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                    }
                },
            )
        }
        sessionKey = vaultCipher.createSession("a horse of a different colour").sessionKey
        runBlocking {
            KoinPlatform.getKoin()
                .getOrCreateScope("session-${prefs.getSessionId()}", named("sessionScope"))
                .get<VaultSession>(named(VAULT_SESSION_HANDLE))
                .bind(sessionKey)
        }
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        root.deleteRecursively()
    }

    // ------------------------------------------------------------- reported outcome

    @Test
    fun `an add that publishes reports true`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"))

        assertTrue(repository().addPasswordEntry(entryData("orchard")))
        assertEquals(listOf("meadow", "orchard"), storedEntries().map { it.entryName })
    }

    @Test
    fun `an add that loses every publish attempt reports false and leaves the vault alone`() = runBlocking<Unit> {
        val sealed = vault(entry("meadow", id = "1"))
        val losing = LosingStorage(storage)

        assertFalse(
            repository(storage = losing).addPasswordEntry(entryData("orchard")),
            "three exhausted retries must not be reported as a save",
        )
        assertEquals(3, losing.attempts, "the fixture must actually exhaust the retries")
        assertContentEquals(sealed, storage.read(user), "nothing may be published on the way out")
    }

    @Test
    fun `an add carries the totp seed and custom fields into the vault`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"))

        assertTrue(
            repository().addPasswordEntry(
                entryData("orchard").copy(
                    totpSeed = "JBSWY3DPEHPK3PXP",
                    customFields = listOf(CustomField(label = "pin", value = "1234", secret = true)),
                ),
            ),
        )

        val stored = storedEntries().first { it.entryName == "orchard" }
        assertEquals("JBSWY3DPEHPK3PXP", stored.totpSeed)
        assertEquals(listOf(CustomField(label = "pin", value = "1234", secret = true)), stored.customFields)
    }

    @Test
    fun `an update that publishes reports true`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"), entry("stable", id = "2"))
        val target = repository().getPasswordEntries().first { it.entryName == "stable" }

        assertTrue(repository().updatePasswordEntry(target.copy(password = "rotated")))
        assertEquals("rotated", storedEntries().first { it.entryName == "stable" }.password)
    }

    @Test
    fun `an update that cannot reach the disk reports false`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"))
        val target = repository().getPasswordEntries().single()

        assertFalse(repository(storage = FailingStorage(storage)).updatePasswordEntry(target.copy(password = "x")))
        assertEquals("pw-meadow", storedEntries().single().password, "the failed write must change nothing")
    }

    @Test
    fun `a delete that removes its target reports true`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"), entry("stable", id = "2"))
        val target = repository().getPasswordEntries().first { it.entryName == "meadow" }

        assertTrue(repository().deletePasswordEntry(target.uuid))
        assertEquals(listOf("stable"), storedEntries().map { it.entryName })
    }

    @Test
    fun `a delete whose target is absent reports false`() = runBlocking<Unit> {
        vault(entry("meadow", id = "1"))

        assertFalse(
            repository().deletePasswordEntry(identity.legacyUuid("nowhere", "nobody")),
            "an absent target is a no-op, and a no-op is not a delete",
        )
        assertEquals(listOf("meadow"), storedEntries().map { it.entryName })
    }

    @Test
    fun `an unreadable vault fails the mutation instead of fabricating success`() = runBlocking<Unit> {
        storage.create(user, "not an envelope of any suite".encodeToByteArray())
        val before = storage.read(user)

        assertFalse(repository().addPasswordEntry(entryData("orchard")))
        assertContentEquals(before, storage.read(user), "an unreadable vault must never be written over")
    }

    // ------------------------------------------------------------- ordinal robustness

    @Test
    fun `an add survives a non-numeric display ordinal already in the vault`() = runBlocking<Unit> {
        // Nothing validates the ordinal on the way in, so a vault synced from another build can
        // carry anything. It must cost nothing: the ordinal is display-only.
        vault(entry("meadow", id = "1"), entry("attic", id = "not-a-number"))

        assertTrue(repository().addPasswordEntry(entryData("orchard")))

        val stored = storedEntries()
        assertEquals(listOf("meadow", "attic", "orchard").sorted(), stored.map { it.entryName }.sorted())
        assertEquals("2", stored.first { it.entryName == "orchard" }.id, "the next ordinal after the numeric max")
    }

    @Test
    fun `appended ordinals are filed numerically, not as strings`() = runBlocking<Unit> {
        // Ten entries so the eleventh forces the "10" < "2" string-sort bug into the open. Names are
        // chosen already in display order so the read path's renumbering never rewrites the vault
        // and the add path's own sort is what lands on disk.
        val names = ('a'..'j').map { "site-$it" }
        vault(*names.mapIndexed { index, name -> entry(name, id = "${index + 1}") }.toTypedArray())

        assertTrue(repository().addPasswordEntry(entryData("site-k")))

        assertEquals(
            (1..11).map { it.toString() },
            storedEntries().map { it.id },
            "ordinal 10 must file after 9, not between 1 and 2",
        )
    }

    // ------------------------------------------------------------- fixtures

    private fun repository(storage: PasswordDatabaseStorage = this.storage) = LocalPasswordRepository(
        userPreferences = prefs,
        coroutinesContextFacade = UnconfinedFacade,
        vaultCipher = vaultCipher,
        storage = storage,
        transferService = NoTransfer,
        entryIdentity = identity,
    )

    /** A suite-5 vault: born migrated, so no test here ever touches the legacy path. */
    private fun vault(vararg entries: PasswordEntry): ByteArray {
        val sealed = vaultCipher.encryptVault(Json.encodeToString(entries.toList()).encodeToByteArray(), sessionKey)
        storage.create(user, sealed)
        return sealed
    }

    private fun storedEntries(): List<PasswordEntry> =
        Json.decodeFromString(vaultCipher.decryptVault(storage.read(user), sessionKey) { null }.plaintext.decodeToString())

    private fun entry(name: String, id: String) = PasswordEntry(
        uuid = identity.legacyUuid(name, "carol"),
        id = id,
        entryName = name,
        username = "carol",
        password = "pw-$name",
        website = "https://$name.example",
        notes = "",
        dateCreated = 500L,
    )

    private fun entryData(name: String) = AddPassword.EntryData(
        entryName = name,
        userName = "carol",
        password = "pw-$name",
        website = "https://$name.example",
        notes = "",
    )

    // ------------------------------------------------------------- fakes

    /** Every conditional publish loses, as if another writer got there first every single time. */
    private class LosingStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        private val count = AtomicInteger()
        val attempts: Int get() = count.get()

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean {
            count.incrementAndGet()
            return false
        }
    }

    /** Publishes nothing: the disk rejects every write. */
    private class FailingStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        override fun write(username: String, encryptedBytes: ByteArray): Unit =
            throw java.io.IOException("simulated write failure")

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean =
            throw java.io.IOException("simulated write failure")
    }

    private object NoTransfer : PasswordTransferService {
        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            hostName: String,
            port: Int,
        ): Outcome<Unit> = error("not a transfer test")

        override suspend fun pullDatabase(hostName: String, port: Int): Outcome<ByteArray> =
            error("not a transfer test")
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("carol", Password("h", "s"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "write-outcome-test"
        override suspend fun clear() = Unit
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
