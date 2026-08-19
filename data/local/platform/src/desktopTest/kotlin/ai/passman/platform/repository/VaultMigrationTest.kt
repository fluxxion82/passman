package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/** A parked reader waits on the other thread's real AES-GCM work, not on a timer. */
private const val PARK_TIMEOUT_SECONDS = 60L

/**
 * The vault's migration contract: reading a legacy RSA-wrapped vault, rewriting it as suite 5, and
 * never losing an entry on the way.
 *
 * The failure this file exists to prevent is not "migration did not run". It is "migration ran and
 * the entries are gone", which is silent, permanent, and happens on the user's real vault on the very
 * first login after an update. So every test here asks one of two questions: *after this, do the
 * entries still come back?* and *after this, is the pre-migration ciphertext still on disk?*
 *
 * Rules this file keeps:
 *
 * 1. **No `kotlin.test.assertFails`.** It catches `Throwable`, so an `OutOfMemoryError` reads as a
 *    pass. Rejections name the type and assert a discriminating property.
 * 2. **Real storage, real envelopes, real Argon2id.** [JvmPasswordDatabaseStorage] writes real files
 *    and [PasswordVaultCipher] does real crypto; the only spy is a [CryptoService] recorder, and it
 *    is there to prove a *negative* — that the v5 path performs no RSA operation at all. A test that
 *    asserts only "the entries came back" cannot tell a migrated vault from one that is still being
 *    read through the RSA identity every single time.
 * 3. **Concurrency is tested, not assumed.** Two threads reaching the vault at once is the dimension
 *    a sequential suite cannot see, and it is where the interesting data-loss bug lives: a save that
 *    lands between a migration's read and its rewrite is invisible to every test in the first half of
 *    this file.
 */
class VaultMigrationTest {

    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var recorder: RecordingCryptoService
    private lateinit var vaultCipher: VaultCipher
    private lateinit var prefs: FakePreferences
    private lateinit var sessionKey: VaultSessionKey

    private val user = "alice"
    private val password = "correct horse battery staple"

    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val rsaPublic = CryptoKey(rsa.public)
    private val rsaPrivate = CryptoKey(rsa.private)

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("vault-migration").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        storage = JvmPasswordDatabaseStorage(platform)
        recorder = RecordingCryptoService(JvmCryptoService())
        vaultCipher = PasswordVaultCipher(recorder)
        prefs = FakePreferences()

        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        // Warmed by login in production; bound directly here because the legacy read
                        // path is the only thing that consults them and it must be able to.
                        scoped(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { rsaPublic }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { rsaPrivate }
                    }
                },
            )
        }
        sessionKey = vaultCipher.createSession(password).sessionKey
        runBlocking { vaultSession().bind(sessionKey) }
    }

    @AfterTest
    fun tearDown() {
        stopKoin()
        root.deleteRecursively()
    }

    // ------------------------------------------------------------- migration

    @Test
    fun `opening a legacy RSA vault returns its entries and rewrites it as suite five`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail", "bank"))

        val read = repository().getPasswordEntries()

        assertEquals(listOf("bank", "gmail"), read.map { it.entryName })
        assertTrue(isSuiteFive(storage.read(user)), "the vault must be rewritten as suite 5")
        assertFalse(storage.read(user).contentEquals(legacy), "the legacy ciphertext must not still be the vault")
    }

    @Test
    fun `migration preserves the pre-migration ciphertext byte-identically`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))

        repository().getPasswordEntries()

        val retained = preMigrationFile()
        assertTrue(retained.isFile, "the downgrade copy must be written as ${retained.name}")
        assertContentEquals(legacy, retained.readBytes(), "the downgrade copy must be the original bytes")

        // And it survives everything that comes after it, including further saves.
        repository().addPasswordEntry(entryData("mail"))
        repository().getPasswordEntries()
        assertContentEquals(legacy, retained.readBytes(), "the downgrade copy is one generation and is never rewritten")
    }

    /**
     * One generation means the *first* one, not the most recent.
     *
     * The sequence this guards is real: migrate, roll the build back, keep using the vault on the old
     * build, then update again. The second migration meets another legacy vault — and overwriting the
     * retained copy with it would replace the user's furthest-back recovery point with a nearer one,
     * which is exactly the wrong direction for an artifact whose only job is going backwards.
     */
    @Test
    fun `a second migration does not replace the retained downgrade copy`() = runBlocking<Unit> {
        val first = legacyVault(entries("gmail"))
        repository().getPasswordEntries()
        assertContentEquals(first, preMigrationFile().readBytes())

        // The downgrade-and-return: an older build put an RSA-wrapped vault back.
        val second = legacyVault(entries("gmail", "added-on-the-old-build"))
        assertEquals(2, repository().getPasswordEntries().size)

        assertTrue(isSuiteFive(storage.read(user)), "the second migration still runs")
        assertFalse(second.contentEquals(first), "fixture precondition: the two legacy vaults differ")
        assertContentEquals(first, preMigrationFile().readBytes(), "the older recovery point is the one worth keeping")
    }

    @Test
    fun `the downgrade copy still decrypts with the legacy RSA key after migration`() = runBlocking<Unit> {
        legacyVault(entries("gmail", "bank"))
        repository().getPasswordEntries()

        val recovered = JvmCryptoService().decryptBytes(preMigrationFile().readBytes(), rsaPrivate)

        assertEquals(
            listOf("gmail", "bank"),
            Json.decodeFromString<List<PasswordEntry>>(recovered.decodeToString()).map { it.entryName },
            "the retained artifact is the downgrade path and has to still be openable by the old build",
        )
    }

    @Test
    fun `a migration whose rewrite fails leaves the original vault byte-for-byte readable`() = runBlocking<Unit> {
        // One entry, so the read does not also renumber: this exercises the pure migration rewrite
        // rather than the ordinary save that a renumber would take.
        val legacy = legacyVault(entries("gmail"))
        val failing = FailingStorage(storage, failReplaceIfUnchanged = true)

        val read = repository(storage = failing).getPasswordEntries()

        assertEquals(listOf("gmail"), read.map { it.entryName }, "a failed migration must still serve the entries")
        assertContentEquals(legacy, storage.read(user), "the vault must be exactly the bytes it started as")

        // The account is fully usable: a retry against working storage completes the migration.
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
        assertTrue(isSuiteFive(storage.read(user)))
    }

    @Test
    fun `a save whose write fails leaves the legacy vault byte-for-byte readable`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val failing = FailingStorage(storage, failWrite = true)

        repository(storage = failing).addPasswordEntry(entryData("bank"))

        assertContentEquals(legacy, storage.read(user), "a failed save must not half-convert the vault")
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    /**
     * The invariant the downgrade path rests on: **no suite-5 vault ever replaces a legacy one
     * without `.premigration.v2` beside it.** If the retention cannot be performed, the migration does
     * not happen — refusing to convert costs the user nothing, and converting without a downgrade copy
     * costs them the only thing that reads their vault on an older build.
     */
    @Test
    fun `a migration that cannot retain the downgrade copy does not rewrite the vault`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val failing = FailingStorage(storage, failRetain = true)

        val read = repository(storage = failing).getPasswordEntries()

        assertEquals(listOf("gmail"), read.map { it.entryName })
        assertContentEquals(legacy, storage.read(user), "no v5 vault may land without the downgrade copy")
        assertFalse(preMigrationFile().exists())
    }

    @Test
    fun `a mutation on a legacy vault retains the downgrade copy before it writes`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))

        repository().addPasswordEntry(entryData("bank"))

        assertContentEquals(legacy, preMigrationFile().readBytes())
        assertTrue(isSuiteFive(storage.read(user)))
        assertEquals(listOf("bank", "gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    @Test
    fun `a mutation that cannot retain the downgrade copy leaves the legacy vault intact`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val failing = FailingStorage(storage, failRetain = true)

        repository(storage = failing).addPasswordEntry(entryData("bank"))

        assertContentEquals(legacy, storage.read(user), "an unretained legacy vault must not be converted")
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    /**
     * "It wrote successfully" is not the property that matters; "it opens again" is.
     *
     * A sealed vault that cannot be reopened is indistinguishable from a good one right up until the
     * next login, by which point the vault it replaced is gone. The seal is therefore decrypted and
     * compared *before* it is allowed near the file — the last moment at which finding out is free —
     * and this test is what makes that check non-vacuous: the cipher here produces envelopes that
     * pass every structural test and authenticate against nothing.
     */
    @Test
    fun `a sealed vault that would not reopen is never published`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val corrupting = CorruptingVaultCipher(vaultCipher)

        repository(vaultCipher = corrupting).addPasswordEntry(entryData("bank"))
        assertContentEquals(legacy, storage.read(user), "a save that would not reopen must not be published")

        repository(vaultCipher = corrupting).getPasswordEntries()
        assertContentEquals(legacy, storage.read(user), "nor may a migration publish one")

        // Unchanged and still fully readable through the ordinary path.
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    /**
     * The other half of the same check, and the half a tag failure cannot cover.
     *
     * Here the envelope authenticates perfectly — it is simply an envelope around the *wrong bytes*.
     * Nothing in AES-GCM objects; only comparing the reopened plaintext to the plaintext the seal was
     * built from notices, which is why the verification is a comparison and not just a decrypt.
     */
    @Test
    fun `a sealed vault that reopens to different content is never published`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val truncating = TruncatingVaultCipher(vaultCipher)

        repository(vaultCipher = truncating).addPasswordEntry(entryData("bank"))
        repository(vaultCipher = truncating).getPasswordEntries()

        assertContentEquals(legacy, storage.read(user), "a seal around the wrong plaintext must not be published")
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    /**
     * The publish that succeeded and the vault that does not open — and the rollback behind it.
     *
     * `sealAndVerify` proves the bytes decrypt *before* they go near the file, which covers everything
     * this process controls. It cannot cover the disk: a bad block, a half-flushed page cache or a
     * filesystem that lied about an fsync all report a successful write and leave a vault nothing can
     * decrypt, on top of the legacy one that could. So the migration reads its own work back and, if
     * that fails, puts the legacy ciphertext straight back — a rollback that cannot lose anything,
     * since the entries on both sides of it are identical.
     *
     * Deleting the read-back, the comparison, or the rollback leaves this test failing with the
     * corrupted vault on disk; without it the whole block was inert, which is the same vacuity the
     * seal-verification tests above were written to close.
     */
    @Test
    fun `a migrated vault that does not read back is rolled back to the legacy ciphertext`() = runBlocking<Unit> {
        // One entry, so the read takes the pure-migration branch rather than the renumbering save.
        val legacy = legacyVault(entries("gmail"))
        val corrupting = CorruptingPublishStorage(storage)

        val read = repository(storage = corrupting).getPasswordEntries()

        assertEquals(listOf("gmail"), read.map { it.entryName }, "the read still serves what it decrypted")
        assertContentEquals(
            legacy,
            storage.read(user),
            "a migrated vault that did not read back must be replaced by the legacy ciphertext again",
        )

        // Not merely intact on disk: the account still opens, and the next attempt still migrates.
        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
        assertTrue(isSuiteFive(storage.read(user)), "the retry completes the migration the rollback undid")
    }

    @Test
    fun `migration converges - repeated reads rewrite the vault exactly once`() = runBlocking<Unit> {
        legacyVault(entries("gmail", "bank"))
        val counting = CountingStorage(storage)
        val repository = repository(storage = counting)

        repeat(4) { assertEquals(2, repository.getPasswordEntries().size) }

        assertEquals(1, counting.writes, "the vault must be rewritten once, not once per read")
        val migrated = storage.read(user)
        repeat(3) { repository.getPasswordEntries() }
        assertContentEquals(migrated, storage.read(user), "a settled vault is never rewritten by a read")
    }

    // --------------------------------------------------------- no RSA on v5

    @Test
    fun `a suite-five vault performs no RSA operation on read or save`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        repository().getPasswordEntries() // performs the migration, which legitimately uses RSA
        assertTrue(recorder.decryptCalls > 0, "the legacy read must have gone through the RSA path")
        recorder.reset()

        val repository = repository()
        repository.getPasswordEntries()
        repository.addPasswordEntry(entryData("bank"))
        repository.updatePasswordEntry(repository.getPasswordEntries().first().copy(notes = "edited"))
        repository.deletePasswordEntry(repository.getPasswordEntries().first().uuid)
        repository.getPasswordEntries()

        assertEquals(0, recorder.decryptCalls, "a migrated vault must never touch the RSA identity again")
        assertEquals(0, recorder.encryptCalls, "a migrated vault must never be re-sealed under RSA")
    }

    @Test
    fun `a v5 read never resolves the legacy RSA key at all`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        repository().getPasswordEntries()

        // No RSA handles in the scope at all: a migrated vault must not need them to open.
        stopKoin()
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) { scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() } }
                },
            )
        }
        vaultSession().bind(sessionKey)

        assertEquals(listOf("gmail"), repository().getPasswordEntries().map { it.entryName })
    }

    // ------------------------------------------------------------ sync pull

    @Test
    fun `an incoming sync payload is persisted as suite five and never re-sealed as RSA`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        repository().getPasswordEntries()
        recorder.reset()
        val peer = Json.encodeToString(entries("peer-entry")).encodeToByteArray()

        val outcome = repository(transferService = FakeTransfer(peer)).pullPasswordDatabase("peer-host")

        assertIs<Outcome.Success<Unit>>(outcome)
        assertTrue(isSuiteFive(storage.read(user)), "a merged sync payload lands as suite 5")
        assertEquals(0, recorder.encryptCalls, "an incoming payload must never be re-sealed as RSA v2")
        assertEquals(
            listOf("gmail", "peer-entry"),
            repository().getPasswordEntries().map { it.entryName },
        )
    }

    @Test
    fun `a sync pull onto a legacy vault retains the downgrade copy`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val peer = Json.encodeToString(entries("peer-entry")).encodeToByteArray()

        assertIs<Outcome.Success<Unit>>(repository(transferService = FakeTransfer(peer)).pullPasswordDatabase("peer-host"))

        assertContentEquals(legacy, preMigrationFile().readBytes())
        assertTrue(isSuiteFive(storage.read(user)))
    }

    // ------------------------------------------------------- the no-wipe guard

    /**
     * The guard that turns every failure in this file from "destroyed" into "unusable": a vault that
     * did not read is never written over. It is load-bearing for migration specifically, because the
     * migration read is the one most likely to fail on a real user's machine — a `.pfx` restored from
     * a different account, a half-copied data directory.
     */
    @Test
    fun `a vault that cannot be decrypted is never written over`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        val otherRsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        stopKoin()
        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
                        scoped(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { CryptoKey(otherRsa.public) }
                        scoped(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { CryptoKey(otherRsa.private) }
                    }
                },
            )
        }
        vaultSession().bind(sessionKey)
        val repository = repository()

        assertEquals(emptyList(), repository.getPasswordEntries())
        repository.addPasswordEntry(entryData("bank"))
        repository.deletePasswordEntry("1")
        repository.updatePasswordEntry(entries("gmail").first())

        assertContentEquals(legacy, storage.read(user), "the only copy of the vault must survive a failed read")
        assertFalse(preMigrationFile().exists(), "a vault that never decrypted has nothing to migrate")
    }

    @Test
    fun `a vault whose plaintext does not parse is never written over`() = runBlocking<Unit> {
        val garbage = JvmCryptoService().encryptBytes("not json at all".encodeToByteArray(), rsaPublic)
        storage.create(user, garbage)
        val repository = repository()

        assertEquals(emptyList(), repository.getPasswordEntries())
        repository.addPasswordEntry(entryData("bank"))

        assertContentEquals(garbage, storage.read(user))
    }

    @Test
    fun `a read without a bound vault session neither returns entries nor writes`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail"))
        vaultSession().destroy()

        val repository = repository()
        assertEquals(emptyList(), repository.getPasswordEntries())
        repository.addPasswordEntry(entryData("bank"))

        assertContentEquals(legacy, storage.read(user), "no session key means no write, ever")
    }

    // ---------------------------------------------------------- concurrency

    /**
     * Two readers reaching an unmigrated vault at once — a double-clicked desktop app, or a UI that
     * lists entries while a sync reconcile runs.
     *
     * Reader A is parked *after* it has read the legacy ciphertext, holding a stale answer. Reader B
     * runs to completion and migrates. A then resumes and tries to publish its own suite-5 rewrite of
     * the same plaintext. Both rewrites carry identical entries here, so nothing is lost either way —
     * what this test protects is the *artifact*: A must not lay a second `.premigration.v2` generation
     * over B's, and must not republish over a vault it no longer recognises.
     */
    @Test
    fun `two readers racing an unmigrated vault leave one downgrade copy and one vault`() = runBlocking<Unit> {
        val legacy = legacyVault(entries("gmail", "bank"))
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, ParkPoint.READ, reached, release)

        val parked = FutureTask { runBlocking { repository(storage = parking).getPasswordEntries() } }
        Thread(parked, "parked-reader").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked reader never read the vault")

        assertEquals(2, repository().getPasswordEntries().size)
        val migrated = storage.read(user)
        assertTrue(isSuiteFive(migrated))

        release.countDown()
        assertEquals(2, parked.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS).size)

        assertContentEquals(legacy, preMigrationFile().readBytes(), "one generation, and it is the original")
        assertEquals(2, repository().getPasswordEntries().size)
    }

    /**
     * The one that actually loses data if it is got wrong.
     *
     * A migration reads the legacy vault and then, before it publishes its rewrite, a save lands with
     * a brand-new entry. If the migration publishes unconditionally it writes the *pre-save* entry
     * list over the save — a silent, permanent loss of whatever the user just typed, on the single
     * most likely occasion for them to be typing: the first session after the update.
     *
     * The rewrite therefore has to be conditional on the vault still holding the bytes the migration
     * read. Removing that condition is the mutation this test is built to catch.
     */
    @Test
    fun `a save that lands mid-migration is not overwritten by the migration`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, ParkPoint.READ, reached, release)

        val migrating = FutureTask { runBlocking { repository(storage = parking).getPasswordEntries() } }
        Thread(migrating, "parked-migration").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked migration never read the vault")

        repository().addPasswordEntry(entryData("typed-during-migration"))
        assertEquals(
            listOf("gmail", "typed-during-migration"),
            repository().getPasswordEntries().map { it.entryName },
        )

        release.countDown()
        migrating.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertEquals(
            listOf("gmail", "typed-during-migration"),
            repository().getPasswordEntries().map { it.entryName },
            "the migration must not publish the entry list it read before the save",
        )
    }

    /**
     * The same race on the branch a real legacy vault actually takes, which the one-entry version
     * above never reaches.
     *
     * A one-entry vault needs no renumbering, so its read goes down the pure-migration branch. Any
     * vault a real user has been *using* does need it: `addPasswordEntry` appends at `max(id)+1`,
     * `updatePasswordEntry` removes and re-appends without re-sorting, `deletePasswordEntry` leaves a
     * gap. Stored order stops matching name order after any of those, so the next read renumbers — and
     * a renumbering read publishes through the ordinary save path, not through the migration.
     *
     * When only the migration's publish was conditional, this is where the loss lived: two entries,
     * one save landing during the first read after an update, and the entry the user had just typed
     * gone with nothing but `.bak` to recover it. The one-entry test passed the whole time.
     */
    @Test
    fun `a save that lands mid-renumber is not overwritten by the renumbering`() = runBlocking<Unit> {
        // Stored gmail-then-bank, so sorting by name renumbers and the read takes the save path.
        legacyVault(entries("gmail", "bank"))
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, ParkPoint.READ, reached, release)

        val migrating = FutureTask { runBlocking { repository(storage = parking).getPasswordEntries() } }
        Thread(migrating, "parked-renumber").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked read never read the vault")

        repository().addPasswordEntry(entryData("typed-during-migration"))
        assertEquals(
            listOf("bank", "gmail", "typed-during-migration"),
            repository().getPasswordEntries().map { it.entryName },
        )

        release.countDown()
        val parkedResult = migrating.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertEquals(
            listOf("bank", "gmail", "typed-during-migration"),
            repository().getPasswordEntries().map { it.entryName },
            "the renumbering must not publish the entry list it read before the save",
        )
        assertEquals(
            listOf("bank", "gmail", "typed-during-migration"),
            parkedResult.map { it.entryName },
            "and having lost, it must re-read rather than hand back the list it renumbered",
        )
    }

    /**
     * A conditional publish on its own does not remove the data loss — it changes whose data is lost.
     *
     * Two saves, the first parked after its read. The second publishes underneath it. If the first
     * then stands down, the entry the user typed *first* is the one that silently disappears, which
     * from their side is the same bug as before wearing the other hat. So a superseded save re-reads
     * the vault that won and applies itself to that instead, and both entries survive.
     *
     * This is a save-versus-save race on a settled suite-5 vault: no migration anywhere near it, so
     * nothing but the re-apply can make it pass.
     */
    @Test
    fun `a save that loses the publish race is re-applied to the vault that won`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        repository().getPasswordEntries() // settle the migration first
        assertTrue(isSuiteFive(storage.read(user)))

        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, ParkPoint.READ, reached, release)

        val parked = FutureTask {
            runBlocking { repository(storage = parking).addPasswordEntry(entryData("typed-first")) }
        }
        Thread(parked, "parked-save").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked save never read the vault")

        repository().addPasswordEntry(entryData("typed-second"))

        release.countDown()
        parked.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertEquals(
            listOf("gmail", "typed-first", "typed-second"),
            repository().getPasswordEntries().map { it.entryName },
            "neither save may be lost: the loser re-applies itself to the winner's vault",
        )
    }

    /** The same race with the roles reversed: the save is the one that resumes late. */
    @Test
    fun `a migration that lands mid-save does not cost the save its entry`() = runBlocking<Unit> {
        legacyVault(entries("gmail"))
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, ParkPoint.READ, reached, release)

        val saving = FutureTask {
            runBlocking { repository(storage = parking).addPasswordEntry(entryData("typed-first")) }
        }
        Thread(saving, "parked-save").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked save never read the vault")

        assertEquals(1, repository().getPasswordEntries().size) // migrates
        release.countDown()
        saving.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertEquals(
            listOf("gmail", "typed-first"),
            repository().getPasswordEntries().map { it.entryName },
            "the save's entry must survive a migration that landed under it",
        )
    }

    // ---------------------------------------------------------------- setup

    private fun repository(
        storage: PasswordDatabaseStorage = this.storage,
        transferService: PasswordTransferService = FakeTransfer(),
        vaultCipher: VaultCipher = this.vaultCipher,
    ) = LocalPasswordRepository(
        userPreferences = prefs,
        coroutinesContextFacade = UnconfinedFacade,
        vaultCipher = vaultCipher,
        storage = storage,
        transferService = transferService,
        entryIdentity = PasswordEntryIdentity(JvmSha256Service()),
    )

    /** A vault in the shape the pre-keyring build wrote: an RSA-OAEP suite-2 envelope. */
    private fun legacyVault(entries: List<PasswordEntry>): ByteArray {
        val bytes = JvmCryptoService().encryptBytes(
            Json.encodeToString(entries).encodeToByteArray(),
            rsaPublic,
        )
        storage.create(user, bytes)
        return bytes
    }

    private fun entries(vararg names: String): List<PasswordEntry> = names.mapIndexed { index, name ->
        PasswordEntry(
            id = (index + 1).toString(),
            dateCreated = 1_000L + index,
            entryName = name,
            password = "p-$name",
            website = "https://$name",
            username = "u-$name",
            notes = "n-$name",
        )
    }

    private fun entryData(name: String) = AddPassword.EntryData(
        entryName = name,
        userName = "u-$name",
        password = "p-$name",
        website = "https://$name",
        notes = "n-$name",
    )

    private fun preMigrationFile(): File =
        File(root, "database/${user.hashCode()}_encrypted_passman.database.premigration.v2")

    private fun isSuiteFive(bytes: ByteArray): Boolean =
        bytes.size > 5 && bytes.copyOfRange(0, 4).contentEquals("PMNV".encodeToByteArray()) && bytes[5] == 5.toByte()

    private suspend fun vaultSession(): VaultSession = KoinPlatform.getKoin()
        .getOrCreateScope("session-${prefs.getSessionId()}", named("sessionScope"))
        .get(named(VAULT_SESSION_HANDLE))

    private enum class ParkPoint { READ }

    // ---------------------------------------------------------------- fakes

    /** Real crypto, counted. The counts are the only way to prove the RSA path is *not* taken. */
    private class RecordingCryptoService(private val delegate: CryptoService) : CryptoService {
        var encryptCalls = 0
            private set
        var decryptCalls = 0
            private set

        override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray {
            encryptCalls++
            return delegate.encryptBytes(plain, publicKey)
        }

        override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray {
            decryptCalls++
            return delegate.decryptBytes(cipher, privateKey)
        }

        fun reset() {
            encryptCalls = 0
            decryptCalls = 0
        }
    }

    /**
     * Real storage with one call held open, so a second caller can overtake the first.
     *
     * A decorator on the production storage rather than a fake: the interaction under test is between
     * the repository's ordering and the store's compare-and-set, and a fake would only prove that the
     * fake agrees with itself. Only the first caller parks.
     */
    private class ParkingStorage(
        private val delegate: PasswordDatabaseStorage,
        private val parkOn: ParkPoint,
        private val reached: CountDownLatch,
        private val release: CountDownLatch,
    ) : PasswordDatabaseStorage by delegate {
        private val armed = AtomicBoolean(true)

        override fun read(username: String): ByteArray {
            // Answer first, then park: the point is to resume holding a *stale* answer.
            val answer = delegate.read(username)
            if (parkOn == ParkPoint.READ) park()
            return answer
        }

        private fun park() {
            if (!armed.compareAndSet(true, false)) return
            reached.countDown()
            check(release.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "the parked caller was never released" }
        }
    }

    private class CountingStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        private val writeCount = AtomicInteger()
        val writes: Int get() = writeCount.get()

        override fun write(username: String, encryptedBytes: ByteArray) {
            writeCount.incrementAndGet()
            delegate.write(username, encryptedBytes)
        }

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean =
            delegate.replaceIfUnchanged(username, expected, replacement).also { if (it) writeCount.incrementAndGet() }
    }

    /**
     * A storage whose publishes fail on demand.
     *
     * [failWrite] fails [replaceIfUnchanged] as well as [write], and that is not laziness — it is what
     * the production implementation does. `JvmPasswordDatabaseStorage.replaceIfUnchanged` is defined
     * *in terms of* `write`, so a disk that rejects the write rejects the conditional replace too. A
     * decorator that failed only the `write` entry point would model a storage that cannot exist, and
     * would silently stop covering the save path the moment saves became conditional — which is
     * exactly what happened.
     */
    private class FailingStorage(
        private val delegate: PasswordDatabaseStorage,
        private val failRetain: Boolean = false,
        private val failReplaceIfUnchanged: Boolean = false,
        private val failWrite: Boolean = false,
    ) : PasswordDatabaseStorage by delegate {
        override fun write(username: String, encryptedBytes: ByteArray) {
            if (failWrite) throw java.io.IOException("simulated write failure")
            delegate.write(username, encryptedBytes)
        }

        override fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean =
            if (failRetain) throw java.io.IOException("simulated retention failure") else delegate.retainPreMigration(username, ciphertext)

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean =
            when {
                failReplaceIfUnchanged -> throw java.io.IOException("simulated rewrite failure")
                failWrite -> throw java.io.IOException("simulated write failure")
                else -> delegate.replaceIfUnchanged(username, expected, replacement)
            }
    }

    /**
     * Publishes something other than what it was handed — once.
     *
     * Stands in for the class of failure the post-publish read-back exists to catch: the write
     * reported success, the file is the right size and the right shape, and the bytes on disk do not
     * decrypt. A bad block, a half-flushed page cache, a filesystem that lied about the fsync.
     *
     * The flip is applied **in place**, to the caller's own array, and that detail is what makes the
     * rollback reachable at all: `migrateVault` rolls back with
     * `replaceIfUnchanged(expected = sealed, replacement = legacy)`, so `sealed` has to describe the
     * bytes that actually landed or the compare-and-set cannot match. Only the first publish is
     * corrupted, so the rollback itself is allowed to land intact.
     */
    private class CorruptingPublishStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        private val armed = AtomicBoolean(true)

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean {
            if (armed.compareAndSet(true, false)) {
                replacement[replacement.lastIndex] = (replacement.last().toInt() xor 1).toByte()
            }
            return delegate.replaceIfUnchanged(username, expected, replacement)
        }
    }

    /**
     * Seals envelopes that are structurally perfect and cryptographically dead: the payload's last
     * byte is flipped after the tag is computed, so the header parses, the suite is 5, the length
     * checks pass, and only the authentication fails. Exactly what a bad block, a truncated flush or
     * a half-swapped key would produce, and exactly what a "did the write succeed?" check cannot see.
     */
    private class CorruptingVaultCipher(private val delegate: VaultCipher) : VaultCipher by delegate {
        override fun encryptVault(plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray =
            delegate.encryptVault(plaintext, sessionKey).also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
    }

    /**
     * Seals a *valid* envelope around the wrong bytes. Decrypting it succeeds; the plaintext that
     * comes back is not the plaintext that went in. Stands in for the class of bug — a stale buffer,
     * an off-by-one slice, a compression step that silently drops the tail — that no authenticated
     * cipher can detect for you.
     */
    private class TruncatingVaultCipher(private val delegate: VaultCipher) : VaultCipher by delegate {
        override fun encryptVault(plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray =
            delegate.encryptVault(plaintext.copyOfRange(0, maxOf(0, plaintext.size - 1)), sessionKey)
    }

    private class FakeTransfer(private val pullBytes: ByteArray = ByteArray(0)) : PasswordTransferService {
        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            hostName: String,
            port: Int,
        ) = Outcome.Success(Unit)

        override suspend fun pullDatabase(hostName: String, port: Int) = Outcome.Success(pullBytes)
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("h", "s"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "vault-migration-test"
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
