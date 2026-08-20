package ai.passman.platform.repository

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.connectivity.model.TrustedDevice
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
import ai.passman.domain.password.GetPassword
import ai.passman.domain.password.model.EntryActivity
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.MessageDigest
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
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.core.qualifier.named
import org.koin.dsl.module
import org.koin.mp.KoinPlatform

/** A parked writer waits on the other thread's real AES-GCM work, not on a timer. */
private const val PARK_TIMEOUT_SECONDS = 60L

/**
 * What identifies a password entry, and what happens to a mutation that names one.
 *
 * The bug this file exists for is not hypothetical and it is not a display glitch. `PasswordEntry.id`
 * is a *display ordinal*: every read sorts by name and reassigns `1..N`. A mutation that captures an
 * id, loses the conditional publish, and re-applies itself to the vault that won is re-applying that
 * id to a list that has been renumbered underneath it — so the delete the user asked for silently
 * becomes a delete of a *different* credential, and both halves of that are reported as success.
 *
 * The fix is a `uuid` that no read reassigns. Two constraints make its derivation the whole design:
 *
 * 1. **Two devices must agree with no coordination.** They upgrade separately and never negotiate
 *    identities, so a pre-existing entry's uuid has to be a pure function of data both already hold
 *    identically. `entryName | 0x00 | username` is that data; `dateCreated` explicitly is not,
 *    because conflict resolution is built on it *differing* between the two copies of one entry.
 * 2. **The first merge after the upgrade must not change behaviour where names are unique.** On two
 *    migrated vaults the uuid is a relabelling of the name, so the uuid-keyed merge has to produce
 *    exactly what the name-keyed merge produced — asserted here against a literal copy of the old
 *    implementation. It diverges in exactly one place, and that place is a fix: two rows that shared
 *    a name but not a username used to collapse into one, and now both survive.
 *
 * The username is in the preimage because the name alone is not a key. Nothing enforces name
 * uniqueness on create, so `[gmail/alice, gmail/bob]` is one tap away — and derived from the name
 * alone those two rows share an identity, at which point deleting one destroys the other, editing one
 * overwrites the other, and opening the second returns the first. The probes at the bottom of this
 * file are that exact vault, and they are permanent.
 *
 * Rules this file keeps, inherited from [VaultMigrationTest]:
 *
 * - **No `kotlin.test.assertFails`.** It catches `Throwable`, so an `OutOfMemoryError` reads as a
 *   pass.
 * - **Real storage, real envelopes, real threads.** The only decorators are the ones that park or
 *   count; everything else is the production class.
 * - **Fixtures are varied deliberately.** The concurrency cases below use a *three*-entry vault,
 *   because a one- or two-entry vault never reaches the renumbering that makes the ordinal move,
 *   and a test that never reaches the failing branch passes for the wrong reason. The namesake
 *   probes carry the same lesson from the other direction: the same-identity bug survived a full
 *   review because no fixture in this file held two entries sharing a name.
 */
class EntryIdentityTest {

    private lateinit var root: File
    private lateinit var platform: Platform
    private lateinit var storage: JvmPasswordDatabaseStorage
    private lateinit var vaultCipher: VaultCipher
    private lateinit var prefs: FakePreferences
    private lateinit var sessionKey: VaultSessionKey

    private val user = "alice"
    private val password = "correct horse battery staple"
    private val identity = PasswordEntryIdentity(JvmSha256Service())

    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val rsaPublic = CryptoKey(rsa.public)
    private val rsaPrivate = CryptoKey(rsa.private)

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("entry-identity").toFile()
        platform = object : Platform() {
            override fun getLocalPath(): String = root.absolutePath
        }
        storage = JvmPasswordDatabaseStorage(platform)
        vaultCipher = PasswordVaultCipher(JvmCryptoService())
        prefs = FakePreferences()

        startKoin {
            modules(
                module {
                    scope(named("sessionScope")) {
                        scoped(named(VAULT_SESSION_HANDLE)) { VaultSession() }
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

    // ------------------------------------------------------------- derivation

    /**
     * The fixed vector. Everything else in this file is downstream of this one equality.
     *
     * The expected value is written out as a literal *and* recomputed from `MessageDigest`, on
     * purpose: the literal catches a change to the derivation, and the recomputation catches a
     * literal that was updated to match a change instead of failing on it.
     */
    @OptIn(ExperimentalUuidApi::class)
    @Test
    fun `a legacy uuid is the first sixteen bytes of sha-256 over the name, a NUL and the username`() {
        val recomputed = Uuid.fromByteArray(
            MessageDigest.getInstance("SHA-256")
                .digest("gmail".encodeToByteArray() + byteArrayOf(0) + "alice".encodeToByteArray())
                .copyOf(16),
        ).toString()

        assertEquals("705e9556-1c40-ed34-8181-2c627cc564d4", identity.legacyUuid("gmail", "alice"))
        assertEquals(recomputed, identity.legacyUuid("gmail", "alice"))
        assertEquals("54fa0e76-9cff-de01-30c1-f2e4f1a083f2", identity.legacyUuid("gmail", "bob"))
        assertEquals("da2a97de-91b6-6145-baae-65d1128cf631", identity.legacyUuid("bank", "u-bank"))
    }

    /**
     * The property the whole design rests on: two devices that never spoke to each other reach the
     * same uuid for the same pre-existing entry.
     *
     * Two independent data directories, two independent vaults, and every field except the two the
     * preimage uses deliberately different — different ordinals, different `dateCreated`, different
     * passwords, different neighbours, different stored order. If the derivation ever grows a third
     * input, the two sides stop agreeing here, and in production the first sync after the upgrade
     * would then duplicate every entry the user owns.
     */
    @Test
    fun `two independently migrated vaults derive the same uuid for the same entry`() = runBlocking<Unit> {
        legacyVault(
            listOf(
                entry("gmail", id = "1", dateCreated = 1_000L),
                entry("bank", id = "2", dateCreated = 1_001L),
            ),
        )
        val here = repository().getPasswordEntries().first { it.entryName == "gmail" }

        val otherRoot = Files.createTempDirectory("entry-identity-peer").toFile()
        try {
            val otherStorage = JvmPasswordDatabaseStorage(
                object : Platform() {
                    override fun getLocalPath(): String = otherRoot.absolutePath
                },
            )
            otherStorage.create(
                user,
                JvmCryptoService().encryptBytes(
                    Json.encodeToString(
                        listOf(
                            entry("zoom", id = "1", dateCreated = 55L),
                            entry("gmail", id = "2", dateCreated = 9_999_999L, password = "totally-different"),
                        ),
                    ).encodeToByteArray(),
                    rsaPublic,
                ),
            )
            val there = repository(storage = otherStorage).getPasswordEntries().first { it.entryName == "gmail" }

            assertEquals(here.uuid, there.uuid, "two devices must migrate to the same identity with no coordination")
            assertEquals(here.username, there.username, "fixture precondition: the two copies are the same login")
            assertNotEquals(here.dateCreated, there.dateCreated, "fixture precondition: the two copies differ")
            assertNotEquals(here.id, there.id, "fixture precondition: the two copies differ")
            assertNotEquals(here.password, there.password, "fixture precondition: the two copies differ")
        } finally {
            otherRoot.deleteRecursively()
        }
    }

    /**
     * `dateCreated` is excluded by design, not by accident — and `username` is included by design.
     *
     * Two copies of one logical entry are *expected* to carry different `dateCreated` values; that is
     * the entire input to conflict resolution. Hashing it in would give the two devices different
     * uuids for the same entry, which is the duplication the derivation exists to prevent. The
     * username is the opposite case: both devices hold it identically, and without it two logins for
     * one site are one identity.
     *
     * The last assertion is about the separator. `("gmail", "alice")` and `("gmai", "lalice")`
     * concatenate to the same bytes, so a preimage that just joins the two fields would give two
     * unrelated entries the same uuid.
     */
    @Test
    fun `the legacy derivation uses the entry name and the username and nothing else`() {
        val one = entry("gmail", id = "1", dateCreated = 1L, password = "a", username = "alice")
        val other = entry("gmail", id = "7", dateCreated = 999_999L, password = "b", username = "alice")

        assertEquals(
            identity.legacyUuid(one.entryName, one.username),
            identity.legacyUuid(other.entryName, other.username),
            "everything the two copies of one entry disagree about must stay out of the preimage",
        )
        assertNotEquals(identity.legacyUuid("gmail", "alice"), identity.legacyUuid("gmail", "bob"))
        assertNotEquals(identity.legacyUuid("gmail", "alice"), identity.legacyUuid("gmai1", "alice"))
        assertNotEquals(identity.legacyUuid("gmail", "alice"), identity.legacyUuid("gmai", "lalice"))
    }

    @Test
    fun `every entry handed out by the repository carries an identity`() = runBlocking<Unit> {
        legacyVault(listOf(entry("gmail", id = "1"), entry("bank", id = "2")))

        val read = repository().getPasswordEntries()

        assertEquals(2, read.size)
        assertTrue(read.none { it.uuid.isEmpty() }, "a caller must never be handed an entry it cannot address")
    }

    // ------------------------------------------------------ createdAt backfill (obligation 1)

    /**
     * The other half of `stabilize`'s job: a pre-upgrade row only ever kept one timestamp, so the
     * honest backfill is `createdAt := dateCreated` — created and last-edited start out equal.
     */
    @Test
    fun `stabilize backfills createdAt from dateCreated for a legacy row`() {
        val legacy = entry("gmail", id = "1", dateCreated = 12_345L)
        assertEquals(0L, legacy.createdAt, "fixture precondition: a legacy row has no createdAt")

        val stabilized = identity.stabilize(listOf(legacy))

        assertEquals(12_345L, stabilized.single().createdAt)
    }

    /**
     * The guard that keeps a garbage row from defeating the fast path on every read forever.
     *
     * `createdAt == 0L` alone is not enough to decide "needs backfilling" — a row with `dateCreated ==
     * 0L` too has nothing to backfill *from*, and without the `dateCreated != 0L` guard such a row
     * would fail the `none { }` check on every single call, forcing a full re-map for the lifetime of
     * the vault. Asserted by reference equality on the returned list: [PasswordEntryIdentity.stabilize]
     * must return the receiver, not a freshly mapped copy, when there is nothing to do.
     */
    @Test
    fun `a row with a zero dateCreated is left alone and does not defeat the fast path`() {
        val garbage = entry("gmail", id = "1", dateCreated = 0L).copy(uuid = identity.newUuid())
        val entries = listOf(garbage)

        val stabilized = identity.stabilize(entries)

        assertTrue(stabilized === entries, "nothing needs backfilling, so stabilize must return the receiver untouched")
        assertEquals(0L, stabilized.single().createdAt, "there is nothing to backfill from")
    }

    // ------------------------------------------------------------ merge parity

    /**
     * **The first sync after the upgrade must not change behaviour at all.**
     *
     * The reference implementation below is a verbatim copy of the merge as it stood before uuids
     * existed. Both sides are run over the same two migrated vaults and compared on every field the
     * old model had; `uuid`, `createdAt` and `activity` — none of which the old model had — are
     * excluded. The real merge backfills `createdAt` (and takes the earlier of the two backfilled
     * values, per `minNonZero`) as a byproduct of stabilizing every row it touches, so leaving it in
     * the comparison would fail this test for a schema-driven field neither vault used to carry, not
     * for a behaviour change.
     *
     * The fixture is built so a difference could actually show: a name present on both sides with a
     * newer `dateCreated` incoming (conflict resolution runs), a name only on the local side, and a
     * name only on the incoming side (both survive).
     */
    @Test
    fun `merging two migrated vaults matches the old name-keyed merge exactly`() = runBlocking<Unit> {
        val existing = listOf(
            entry("bank", id = "1", dateCreated = 100L),
            entry("gmail", id = "2", dateCreated = 100L),
        )
        val incoming = listOf(
            entry("gmail", id = "1", dateCreated = 200L, password = "rotated"),
            entry("zoom", id = "2", dateCreated = 50L),
        )
        legacyVault(existing)

        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(incoming).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries()
        assertEquals(
            legacyNameKeyedMerge(existing, incoming),
            merged.map { it.copy(uuid = "", createdAt = 0, activity = emptyList()) },
            "the uuid-keyed merge must be indistinguishable from the name-keyed one on migrated vaults",
        )
        // And the fixture really did exercise all three cases.
        assertEquals(listOf("bank", "gmail", "zoom"), merged.map { it.entryName })
        assertEquals("rotated", merged.first { it.entryName == "gmail" }.password)
    }

    /**
     * The rename that used to duplicate.
     *
     * Under the name-keyed merge a renamed entry was a *new key*, so the peer's copy under the old
     * name came back and the user ended up owning both. The uuid survives the rename, so the peer's
     * copy resolves to the same entry and loses on `dateCreated` like any other stale update.
     */
    @Test
    fun `a renamed entry merges as an update rather than a duplicate`() = runBlocking<Unit> {
        val original = listOf(entry("gmail", id = "1", dateCreated = 100L), entry("bank", id = "2", dateCreated = 100L))
        legacyVault(original)
        val repository = repository()

        val gmail = repository.getPasswordEntries().first { it.entryName == "gmail" }
        repository.updatePasswordEntry(gmail.copy(entryName = "mail"))
        assertEquals(listOf("bank", "mail"), repository.getPasswordEntries().map { it.entryName })

        // The peer has not seen the rename and has not upgraded: its payload has no uuid at all.
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(original).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        assertEquals(
            listOf("bank", "mail"),
            repository.getPasswordEntries().map { it.entryName },
            "the peer's pre-rename copy is the same entry, not a second one",
        )
    }

    /**
     * The namesake that used to disappear.
     *
     * `associateBy { entryName }` kept the last entry for a name and dropped the rest, so two logins
     * on the same site collapsed into one on the next sync. Entries created after the upgrade carry
     * uuids that were never a function of their name, so they survive it.
     *
     * The limitation this does *not* remove is deliberate and is asserted separately below.
     */
    @Test
    fun `two entries sharing a name both survive a merge once they have their own identities`() = runBlocking<Unit> {
        legacyVault(listOf(entry("bank", id = "1", dateCreated = 100L)))
        val repository = repository()
        repository.getPasswordEntries() // settle the migration
        repository.addPasswordEntry(entryData("gmail", userName = "alice"))
        repository.addPasswordEntry(entryData("gmail", userName = "bob"))

        val before = repository.getPasswordEntries()
        assertEquals(2, before.count { it.entryName == "gmail" }, "fixture precondition: two entries share a name")
        val alice = before.first { it.username == "alice" }

        val peer = listOf(alice.copy(password = "rotated", dateCreated = alice.dateCreated + 1))
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(peer).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val after = repository.getPasswordEntries()
        assertEquals(3, after.size, "the namesake must not be swallowed by the entry it shares a name with")
        assertEquals("rotated", after.first { it.username == "alice" }.password)
        assertEquals("p-gmail", after.first { it.username == "bob" }.password)
    }

    /**
     * The one place the first merge after the upgrade is *not* unchanged, and it is the fix.
     *
     * Two entries that already shared a name before the upgrade used to derive one identity, so the
     * merge collapsed them exactly as the name-keyed merge did — the reference below still shows
     * `bob` swallowing `alice`. With the username in the preimage they are two identities and both
     * survive. This is a data-loss fix, so the divergence from the reference is asserted rather than
     * avoided.
     */
    @Test
    fun `pre-existing namesakes with different usernames both survive the first merge`() = runBlocking<Unit> {
        val duplicated = listOf(
            entry("gmail", id = "1", dateCreated = 100L, username = "alice"),
            entry("gmail", id = "2", dateCreated = 200L, username = "bob"),
        )
        legacyVault(duplicated)

        val outcome = repository(transferService = FakeTransfer("[]".encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        assertEquals(
            listOf("alice", "bob"),
            repository().getPasswordEntries().map { it.username },
            "two logins for one site are two entries, and a merge must not eat one of them",
        )
        assertEquals(
            listOf("bob"),
            legacyNameKeyedMerge(duplicated, emptyList()).map { it.username },
            "reference precondition: this is exactly what the old merge destroyed",
        )
    }

    /**
     * The residual case the derivation genuinely cannot separate, stated so nobody rediscovers it.
     *
     * Two entries sharing a name *and* a username have no third field two devices are guaranteed to
     * agree on, so they derive one identity and still collapse on merge. What must not happen is the
     * local damage: the mutations act on one row, so the pair costs the user an ambiguity rather
     * than a credential.
     */
    @Test
    fun `entries sharing a name and a username still share one identity`() = runBlocking<Unit> {
        legacyVault(
            listOf(
                entry("gmail", id = "1", dateCreated = 100L, username = "alice", password = "first"),
                entry("gmail", id = "2", dateCreated = 200L, username = "alice", password = "second"),
            ),
        )

        val twins = repository().getPasswordEntries()

        assertEquals(2, twins.size, "a read never drops a row")
        assertEquals(twins[0].uuid, twins[1].uuid, "there is nothing left to tell them apart")
    }

    // ------------------------------------------------- activity & createdAt merge

    /**
     * Obligation 4, direction one: the incoming row wins on `dateCreated`. Both sides carry a
     * disjoint activity record; the union must keep all three, not only the winner's own list.
     */
    @Test
    fun `a merge unions activity from both sides when the incoming row wins on dateCreated`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 100L).copy(
            createdAt = 100L,
            activity = listOf(EntryActivity(100L, EntryActivity.KIND_CREATED)),
        )
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 200L, password = "rotated").copy(
            createdAt = 50L,
            activity = listOf(EntryActivity(50L, "peer-only"), EntryActivity(200L, EntryActivity.KIND_EDITED)),
        )
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals("rotated", merged.password, "fixture precondition: the incoming row wins the scalar comparison")
        assertEquals(
            listOf(
                EntryActivity(50L, "peer-only"),
                EntryActivity(100L, EntryActivity.KIND_CREATED),
                EntryActivity(200L, EntryActivity.KIND_EDITED),
            ),
            merged.activity,
            "both sides' disjoint records must survive, not just the winner's own list",
        )
    }

    /**
     * Obligation 4, direction two — the one that fails a winner-arm-only implementation. The
     * *local* row wins on `dateCreated` here, so a merge that only unions inside the "incoming wins"
     * branch would drop the incoming row's disjoint record and never look at it again.
     */
    @Test
    fun `a merge unions activity from both sides when the existing row wins on dateCreated`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 200L, password = "kept").copy(
            createdAt = 200L,
            activity = listOf(EntryActivity(100L, EntryActivity.KIND_CREATED), EntryActivity(200L, EntryActivity.KIND_EDITED)),
        )
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 100L).copy(
            createdAt = 50L,
            activity = listOf(EntryActivity(50L, "peer-only")),
        )
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals("kept", merged.password, "fixture precondition: the existing row wins the scalar comparison")
        assertEquals(
            listOf(
                EntryActivity(50L, "peer-only"),
                EntryActivity(100L, EntryActivity.KIND_CREATED),
                EntryActivity(200L, EntryActivity.KIND_EDITED),
            ),
            merged.activity,
            "the losing side's disjoint record must still be unioned in, not discarded",
        )
    }

    /** Obligation 5. */
    @Test
    fun `merge dedupes an activity record both sides already hold`() = runBlocking<Unit> {
        val shared = EntryActivity(100L, EntryActivity.KIND_CREATED)
        val local = entry("gmail", id = "1", dateCreated = 100L).copy(createdAt = 100L, activity = listOf(shared))
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 200L).copy(
            createdAt = 100L,
            activity = listOf(shared, EntryActivity(200L, EntryActivity.KIND_EDITED)),
        )
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals(
            listOf(shared, EntryActivity(200L, EntryActivity.KIND_EDITED)),
            merged.activity,
            "a record both sides already hold must appear once, not twice",
        )
    }

    /** Obligation 6. */
    @Test
    fun `merge takes the earlier createdAt even when the other side wins on dateCreated`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 500L).copy(createdAt = 500L)
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 100L).copy(createdAt = 10L)
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals(500L, merged.dateCreated, "fixture precondition: the existing row wins on dateCreated")
        assertEquals(10L, merged.createdAt, "the earlier createdAt must be kept even though its row lost the scalar comparison")
    }

    /**
     * Obligation 6, the other direction. Every other `createdAt` fixture in this file happens to give
     * the *winning* row the smaller-or-equal `createdAt`, which leaves `minNonZero(current.createdAt,
     * entry.createdAt)` in the "incoming wins" arm indistinguishable from a bare `entry.createdAt`: the
     * winner's own value already is the minimum, so dropping the `minNonZero` call there would still
     * pass. Here the *incoming* row wins on `dateCreated` but carries the *later* `createdAt`, so only
     * an actual `min()` produces the local row's earlier value.
     */
    @Test
    fun `merge takes the local row's earlier createdAt even when the incoming row wins on dateCreated`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 100L).copy(createdAt = 10L)
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 200L, password = "rotated").copy(createdAt = 999L)
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals(200L, merged.dateCreated, "fixture precondition: the incoming row wins on dateCreated")
        assertEquals(10L, merged.createdAt, "the local row's earlier createdAt must survive even though its row lost the scalar comparison")
    }

    /** Obligation 3, merge half — the decode/round-trip half is pinned in `PasswordEntryCompatTest`. */
    @Test
    fun `an unrecognised activity kind survives a merge and is re-encoded verbatim`() = runBlocking<Unit> {
        val exotic = EntryActivity(150L, "totp-viewed", "phone-3")
        val local = entry("gmail", id = "1", dateCreated = 100L).copy(
            createdAt = 100L,
            activity = listOf(EntryActivity(100L, EntryActivity.KIND_CREATED)),
        )
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 200L).copy(createdAt = 100L, activity = listOf(exotic))
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertTrue(merged.activity.contains(exotic), "an unrecognised kind must survive the merge unchanged")
        assertEquals(
            exotic,
            storedEntries().single { it.entryName == "gmail" }.activity.first { it.at == 150L },
            "and must be re-encoded on disk verbatim, not coerced to a fallback value",
        )
    }

    /** Obligation 7, merge half — the append half is below. */
    @Test
    fun `cap holds after a merge, keeping the newest`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 14L).copy(
            activity = (0L..14L).map { EntryActivity(it, EntryActivity.KIND_EDITED) },
        )
        legacyVault(listOf(local))

        val incoming = entry("gmail", id = "1", dateCreated = 29L).copy(
            activity = (15L..29L).map { EntryActivity(it, EntryActivity.KIND_EDITED) },
        )
        val outcome = repository(transferService = FakeTransfer(Json.encodeToString(listOf(incoming)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcome)

        val merged = repository().getPasswordEntries().single { it.entryName == "gmail" }
        assertEquals(20, merged.activity.size, "capped at MAX_ACTIVITY")
        assertEquals((10L..29L).toList(), merged.activity.map { it.at }, "the newest 20 survive, oldest dropped")
    }

    /** Obligation 7, append half. */
    @Test
    fun `cap holds after an append, keeping the newest`() = runBlocking<Unit> {
        val seeded = entry("gmail", id = "1", dateCreated = 19L).copy(
            activity = (0L..19L).map { EntryActivity(it, EntryActivity.KIND_EDITED) },
        )
        legacyVault(listOf(seeded))
        val repository = repository()
        val before = repository.getPasswordEntries().single()
        assertEquals(20, before.activity.size, "fixture precondition: already at the cap")
        assertEquals(0L, before.activity.first().at, "fixture precondition: the oldest record is at=0")

        repository.updatePasswordEntry(before.copy(password = "rotated"))

        val after = repository.getPasswordEntries().single()
        assertEquals(20, after.activity.size, "still capped after the append")
        assertTrue(after.activity.none { it.at == 0L }, "the oldest record must be dropped to make room")
        assertEquals(after.dateCreated, after.activity.last().at, "the newest record is the one just appended")
    }

    /**
     * Obligation 10. `entry.copy(...)` in `updatePasswordEntry` must source `createdAt` and `activity`
     * from the *stored* row, not from whatever the caller happened to be holding — a caller that read
     * the entry before another device's merge landed would otherwise roll the history back.
     */
    @Test
    fun `update carries createdAt and activity from the stored entry, not a stale caller copy`() = runBlocking<Unit> {
        settledVault("gmail")
        val repository = repository()
        val stored = repository.getPasswordEntries().single()
        val stale = stored.copy(
            password = "rotated",
            createdAt = 1L,
            activity = listOf(EntryActivity(1L, "phantom")),
        )

        repository.updatePasswordEntry(stale)

        val after = repository.getPasswordEntries().single()
        assertEquals(stored.createdAt, after.createdAt, "createdAt must come from the stored row, not the caller's stale copy")
        assertTrue(after.activity.none { it.kind == "phantom" }, "the caller's foreign activity history must not overwrite the real one")
        assertEquals(stored.activity.size + 1, after.activity.size, "exactly one record is appended")
        assertEquals(after.dateCreated, after.activity.last().at, "the appended record's at equals the new dateCreated")
    }

    /**
     * Obligation 8, and the test that pins the total-order sort. With `sortedBy { it.at }` (stable,
     * so ties keep concatenation order) this exact fixture drops the *other* record at the tied
     * timestamp instead, so asserting the total-order outcome fails under that simplification.
     */
    @Test
    fun `merging twice equals merging once, including at the cap boundary with a tied timestamp`() = runBlocking<Unit> {
        val local = entry("gmail", id = "1", dateCreated = 20L, password = "local").copy(
            createdAt = 5L,
            activity = listOf(EntryActivity(1L, "z")) + (2L..20L).map { EntryActivity(it, EntryActivity.KIND_EDITED) },
        )
        legacyVault(listOf(local))

        val peer = entry("gmail", id = "1", dateCreated = 25L, password = "peer").copy(
            createdAt = 3L,
            activity = listOf(EntryActivity(1L, "a")),
        )
        val peerBytes = Json.encodeToString(listOf(peer)).encodeToByteArray()

        val first = repository(transferService = FakeTransfer(peerBytes)).pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(first)
        val afterFirst = repository().getPasswordEntries().single { it.entryName == "gmail" }

        assertEquals(20, afterFirst.activity.size, "capped at MAX_ACTIVITY")
        assertEquals(EntryActivity(1L, "z"), afterFirst.activity.first(), "the total order keeps 'z' over the tied 'a'")
        assertTrue(afterFirst.activity.none { it.at == 1L && it.kind == "a" }, "the tied loser must be dropped")
        assertEquals(3L, afterFirst.createdAt, "the earlier createdAt wins even though its row also won dateCreated")

        val second = repository(transferService = FakeTransfer(peerBytes)).pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(second)
        val afterSecond = repository().getPasswordEntries().single { it.entryName == "gmail" }

        assertEquals(afterFirst.activity, afterSecond.activity, "merging the same peer payload again must not change the result")
        assertEquals(afterFirst.createdAt, afterSecond.createdAt, "nor the createdAt")
    }

    /**
     * Obligation 9. Two independent vaults, each merging the other's row in — vault A takes X local
     * and Y as the incoming peer, vault B takes Y local and X as the incoming peer. The tied record at
     * `at=60` is what makes this pin the total-order sort rather than `sortedBy { it.at }`: a stable
     * sort keeps a tied pair in concatenation order, which is reversed between the two directions, so
     * the two vaults would disagree on which of the tied pair survives.
     */
    @Test
    fun `merge(a,b) and merge(b,a) agree on activity and createdAt`() = runBlocking<Unit> {
        val x = entry("gmail", id = "1", dateCreated = 100L, password = "x").copy(
            createdAt = 10L,
            activity = listOf(EntryActivity(10L, "created"), EntryActivity(60L, "m")),
        )
        val y = entry("gmail", id = "1", dateCreated = 200L, password = "y").copy(
            createdAt = 5L,
            activity = listOf(EntryActivity(5L, "seeded"), EntryActivity(60L, "q"), EntryActivity(150L, "edited")),
        )

        // Vault A (the class's shared storage/root): X is local, Y arrives as the peer.
        legacyVault(listOf(x))
        val outcomeA = repository(transferService = FakeTransfer(Json.encodeToString(listOf(y)).encodeToByteArray()))
            .pullPasswordDatabase(peerDevice("peer-host"))
        assertIs<Outcome.Success<Unit>>(outcomeA)
        val afterA = repository().getPasswordEntries().single { it.entryName == "gmail" }

        // Vault B: an entirely separate storage root, with Y local and X arriving as the peer.
        val otherRoot = Files.createTempDirectory("entry-identity-commute").toFile()
        try {
            val otherStorage = JvmPasswordDatabaseStorage(
                object : Platform() {
                    override fun getLocalPath(): String = otherRoot.absolutePath
                },
            )
            otherStorage.create(
                user,
                JvmCryptoService().encryptBytes(Json.encodeToString(listOf(y)).encodeToByteArray(), rsaPublic),
            )
            val outcomeB = repository(
                storage = otherStorage,
                transferService = FakeTransfer(Json.encodeToString(listOf(x)).encodeToByteArray()),
            ).pullPasswordDatabase(peerDevice("peer-host"))
            assertIs<Outcome.Success<Unit>>(outcomeB)
            val afterB = repository(storage = otherStorage).getPasswordEntries().single { it.entryName == "gmail" }

            assertEquals(afterA.activity, afterB.activity, "merge(a,b) and merge(b,a) must agree on activity")
            assertEquals(afterA.createdAt, afterB.createdAt, "and on createdAt")
        } finally {
            otherRoot.deleteRecursively()
        }
    }

    // ------------------------------------------------------- addressing a row

    /**
     * The reviewer's probe, as a permanent regression test.
     *
     * Vault `[1 apple, 2 bank, 3 cat]`. A delete of *cat* is parked after it has read the vault. A
     * rival adds `amazon`, and the read that follows renumbers — `bank` is now 3 and `cat` is 4. The
     * parked delete then loses its conditional publish and re-applies itself.
     *
     * Keyed on the ordinal it captured, the retry deletes `bank` and leaves `cat`, and reports
     * success for a delete that removed the wrong credential. Keyed on the uuid it resolves out of
     * the list it is handed, it deletes `cat`.
     *
     * Three entries, not one: a smaller vault never renumbers, so the branch this is about is never
     * reached and the test would pass no matter what the code did.
     */
    @Test
    fun `a delete that loses the publish race still removes the entry it was asked to remove`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val repository = repository()
        val cat = repository.getPasswordEntries().first { it.entryName == "cat" }
        assertEquals("3", cat.id, "fixture precondition: cat is the third ordinal")

        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, reached, release)

        val parked = FutureTask {
            runBlocking { repository(storage = parking).deletePasswordEntry(cat.uuid) }
        }
        Thread(parked, "parked-delete").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked delete never read the vault")

        repository.addPasswordEntry(entryData("amazon"))
        val renumbered = repository.getPasswordEntries()
        assertEquals(listOf("amazon", "apple", "bank", "cat"), renumbered.map { it.entryName })
        assertEquals("3", renumbered.first { it.entryName == "bank" }.id, "the ordinal cat held now names bank")

        release.countDown()
        parked.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        assertEquals(
            listOf("amazon", "apple", "bank"),
            repository.getPasswordEntries().map { it.entryName },
            "bank must survive and cat must be gone",
        )
    }

    /** The same race for an edit: the retry must rewrite `cat`, not whatever inherited its number. */
    @Test
    fun `an update that loses the publish race still edits the entry it was asked to edit`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val repository = repository()
        val cat = repository.getPasswordEntries().first { it.entryName == "cat" }

        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val parking = ParkingStorage(storage, reached, release)

        val parked = FutureTask {
            runBlocking { repository(storage = parking).updatePasswordEntry(cat.copy(password = "edited")) }
        }
        Thread(parked, "parked-update").start()
        assertTrue(reached.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS), "the parked update never read the vault")

        repository.addPasswordEntry(entryData("amazon"))
        repository.getPasswordEntries() // renumbers: bank takes the ordinal cat had

        release.countDown()
        parked.get(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        // Checked before the next read renumbers and hides it. The retry writes the ordinal the
        // *vault* holds, not the one the caller was carrying from before the renumbering; taking the
        // caller's would leave two rows sharing a number, which the next read normally tidies away
        // but which is a duplicate key in any list rendering them, and survives on disk whenever
        // that tidying read cannot publish.
        val stored = storedEntries()
        assertEquals(
            stored.size,
            stored.map { it.id }.toSet().size,
            "the retry must not stamp a stale ordinal onto the published vault",
        )

        val after = repository.getPasswordEntries()
        assertEquals("edited", after.first { it.entryName == "cat" }.password)
        assertEquals("p-bank", after.first { it.entryName == "bank" }.password, "bank must not have been edited")
        assertEquals(listOf("amazon", "apple", "bank", "cat"), after.map { it.entryName })
    }

    /**
     * A delete of something that is not there deletes nothing — and does not write.
     *
     * The failure mode this closes is the same one the probe above demonstrates, in its quiet form:
     * an ordinal always matches *something*, so a stale target used to be indistinguishable from a
     * live one. A uuid that is no longer in the vault matches nothing, which is the honest answer.
     */
    @Test
    fun `a delete whose target is gone is a no-op and not a delete of its neighbour`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val counting = CountingStorage(storage)
        val repository = repository(storage = counting)
        val before = storage.read(user)

        repository.deletePasswordEntry(identity.legacyUuid("never-existed", "nobody"))

        assertEquals(0, counting.writes, "nothing to delete means nothing to publish")
        assertContentEquals(before, storage.read(user), "the vault must be byte-identical")
        assertEquals(listOf("apple", "bank", "cat"), repository.getPasswordEntries().map { it.entryName })
    }

    @Test
    fun `a batch delete reports zero when none of its targets are there`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val counting = CountingStorage(storage)
        val repository = repository(storage = counting)

        val removed = repository.deletePasswordEntries(setOf("1", "2", identity.legacyUuid("never-existed", "nobody")))

        assertEquals(0, removed, "a delete that removed nothing must not report a count")
        assertEquals(0, counting.writes)
        assertEquals(listOf("apple", "bank", "cat"), repository.getPasswordEntries().map { it.entryName })
    }

    @Test
    fun `a batch delete reports only the targets that were actually present`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val repository = repository()
        val bank = repository.getPasswordEntries().first { it.entryName == "bank" }

        val removed = repository.deletePasswordEntries(setOf(bank.uuid, identity.legacyUuid("never-existed", "nobody")))

        assertEquals(1, removed)
        assertEquals(listOf("apple", "cat"), repository.getPasswordEntries().map { it.entryName })
    }

    /**
     * An update whose target has been deleted underneath it does not resurrect it.
     *
     * Addressed by ordinal this used to be an unconditional remove-and-append, so an edit of an
     * entry another device had already deleted silently put it back — under whatever ordinal the
     * caller happened to be holding.
     */
    @Test
    fun `an update whose target is gone neither resurrects it nor rewrites a neighbour`() = runBlocking<Unit> {
        settledVault("apple", "bank", "cat")
        val repository = repository()
        val cat = repository.getPasswordEntries().first { it.entryName == "cat" }
        repository.deletePasswordEntry(cat.uuid)

        val counting = CountingStorage(storage)
        repository(storage = counting).updatePasswordEntry(cat.copy(password = "edited"))

        assertEquals(0, counting.writes)
        assertEquals(listOf("apple", "bank"), repository.getPasswordEntries().map { it.entryName })
        assertEquals("p-bank", repository.getPasswordEntries().first { it.entryName == "bank" }.password)
    }

    // ------------------------------------------------------- the namesake probes

    /*
     * Vault `[gmail/alice, gmail/bob, zoom/z]`, and every mutation run against it.
     *
     * Derived from the name alone, `alice` and `bob` are one identity, and every one of these
     * operations resolves its target across the whole list. The measured result on that build was:
     * deleting `alice` also destroyed `bob`; editing `alice` overwrote `bob` with a copy of `alice`;
     * a batch delete of one uuid reported `removed = 2`; and looking `bob` up returned `alice`.
     * Nothing about it needed a race — it needed one tap, on a vault a user can build by accident,
     * because nothing enforces name uniqueness on create.
     *
     * `zoom/z` is in the fixture so a bug that empties the vault is distinguishable from one that
     * removes the twins.
     *
     * Every one of them targets **bob**, the *second* twin, and that is not decoration. Under a
     * name-only preimage bob's uuid is alice's, so every mutation below resolves to alice — and the
     * hardening then makes it act on alice cleanly, which is a correct-looking result for the wrong
     * row. Targeting the first twin would pass under both the fix and the bug. What the hardening is
     * for is covered separately by
     * [a mutation touches one row even when two rows share an identity].
     */

    @Test
    fun `deleting one of two entries sharing a name leaves the other untouched`() = runBlocking<Unit> {
        namesakeVault()
        val repository = repository()
        val bob = repository.getPasswordEntries().first { it.username == "bob" }

        repository.deletePasswordEntry(bob.uuid)

        val after = repository.getPasswordEntries()
        assertEquals(listOf("alice", "z"), after.map { it.username }, "alice must survive bob being deleted")
        assertEquals("p-gmail", after.first { it.username == "alice" }.password, "and must be untouched")
    }

    @Test
    fun `editing one of two entries sharing a name leaves the other untouched`() = runBlocking<Unit> {
        namesakeVault()
        val repository = repository()
        val bob = repository.getPasswordEntries().first { it.username == "bob" }

        repository.updatePasswordEntry(bob.copy(password = "rotated"))

        val after = repository.getPasswordEntries()
        assertEquals(listOf("alice", "bob", "z"), after.map { it.username }, "no row may be overwritten")
        assertEquals("rotated", after.first { it.username == "bob" }.password)
        assertEquals("p-gmail", after.first { it.username == "alice" }.password, "alice must not have been edited")
    }

    @Test
    fun `a batch delete of one namesake removes that row and reports one`() = runBlocking<Unit> {
        namesakeVault()
        val repository = repository()
        val bob = repository.getPasswordEntries().first { it.username == "bob" }

        val removed = repository.deletePasswordEntries(setOf(bob.uuid))

        assertEquals(1, removed, "a selection of one must never report a delete of two")
        assertEquals(listOf("alice", "z"), repository.getPasswordEntries().map { it.username })
    }

    /**
     * The lookup half. `GetPassword` is what the detail screen opens, so a uuid that resolves to the
     * wrong twin means editing the row the user did not choose — every write path can be correct and
     * the user still loses the credential they were looking at.
     */
    @Test
    fun `a lookup returns the entry whose uuid was asked for`() = runBlocking<Unit> {
        namesakeVault()
        val repository = repository()
        val entries = repository.getPasswordEntries()
        val alice = entries.first { it.username == "alice" }
        val bob = entries.first { it.username == "bob" }
        val getPassword = GetPassword(repository)

        assertEquals("alice", getPassword(alice.uuid)?.username)
        assertEquals("bob", getPassword(bob.uuid)?.username, "opening the second twin must not return the first")
    }

    /**
     * The hardening, on the pair the derivation genuinely cannot separate.
     *
     * Same name *and* same username, so they really do share a uuid and no widening of the preimage
     * would help. What the mutations must do is degrade to touching one row: the user loses track of
     * which of two identical-looking logins they edited, rather than losing one of them.
     */
    @Test
    fun `a mutation touches one row even when two rows share an identity`() = runBlocking<Unit> {
        legacyVault(
            listOf(
                entry("gmail", id = "1", dateCreated = 1_000L, username = "alice", password = "first"),
                entry("gmail", id = "2", dateCreated = 1_001L, username = "alice", password = "second"),
                entry("zoom", id = "3", dateCreated = 1_002L, username = "z"),
            ),
        )
        val repository = repository()
        val twins = repository.getPasswordEntries().filter { it.entryName == "gmail" }
        assertEquals(2, twins.size, "fixture precondition: two rows share a name and a username")
        assertEquals(twins[0].uuid, twins[1].uuid, "fixture precondition: they share an identity")

        repository.updatePasswordEntry(twins[0].copy(password = "rotated"))
        val edited = repository.getPasswordEntries()
        assertEquals(3, edited.size, "an edit must not remove a row")
        assertEquals(
            listOf("rotated", "second"),
            edited.filter { it.entryName == "gmail" }.map { it.password },
            "exactly one of the two rows is rewritten",
        )

        assertEquals(1, repository.deletePasswordEntries(setOf(twins[0].uuid)), "a batch delete takes one row")
        assertEquals(listOf("gmail", "zoom"), repository.getPasswordEntries().map { it.entryName })

        repository.deletePasswordEntry(twins[0].uuid)
        assertEquals(listOf("zoom"), repository.getPasswordEntries().map { it.entryName })
    }

    // ------------------------------------------------- ordinals that were not published

    /**
     * A read whose renumbering did not reach the disk hands back the ordinals that *are* on the disk.
     *
     * Returning the uncommitted numbering would describe a vault that does not exist. It is no longer
     * dangerous — nothing addresses an entry by the ordinal any more — but it is still a lie, and the
     * display order (by name) is the part the caller actually wanted.
     */
    @Test
    fun `a read whose renumbering could not publish returns the stored ordinals`() = runBlocking<Unit> {
        settledVault("apple", "cat")
        repository().addPasswordEntry(entryData("bank")) // appended at ordinal 3, out of name order
        assertEquals(
            listOf("1", "2", "3"),
            storedEntries().map { it.id },
            "fixture precondition: the stored order is apple, cat, bank",
        )
        assertEquals(listOf("apple", "cat", "bank"), storedEntries().map { it.entryName })

        val read = repository(storage = FailingStorage(storage)).getPasswordEntries()

        assertEquals(listOf("apple", "bank", "cat"), read.map { it.entryName }, "still sorted for display")
        assertEquals(listOf("1", "3", "2"), read.map { it.id }, "but carrying the ordinals the vault holds")
    }

    /**
     * The other non-published branch: three attempts, every one of them superseded.
     *
     * A storage that never lets a conditional publish win drives the loop to exhaustion without a
     * second thread, so this reaches the fall-through the [FailingStorage] case above never touches.
     */
    @Test
    fun `a read that loses every publish attempt returns the stored ordinals`() = runBlocking<Unit> {
        settledVault("apple", "cat")
        repository().addPasswordEntry(entryData("bank"))
        assertEquals(listOf("apple", "cat", "bank"), storedEntries().map { it.entryName })

        val losing = LosingStorage(storage)
        val read = repository(storage = losing).getPasswordEntries()

        assertEquals(3, losing.attempts, "the fixture must actually exhaust the retries")
        assertEquals(listOf("apple", "bank", "cat"), read.map { it.entryName })
        assertEquals(listOf("1", "3", "2"), read.map { it.id }, "the ordinals the vault still holds")
    }

    // ---------------------------------------------------------------- helpers

    /** The merge exactly as it stood before uuids existed. Do not change it — it is the reference. */
    private fun legacyNameKeyedMerge(
        existing: List<PasswordEntry>,
        incoming: List<PasswordEntry>,
    ): List<PasswordEntry> {
        val byName = existing.associateBy { it.entryName }.toMutableMap()
        for (entry in incoming) {
            val current = byName[entry.entryName]
            if (current == null || entry.dateCreated > current.dateCreated) {
                byName[entry.entryName] = entry
            }
        }
        return byName.values
            .sortedBy { it.entryName.lowercase() }
            .mapIndexed { index, e -> e.copy(id = (index + 1).toString()) }
    }

    private fun repository(
        storage: PasswordDatabaseStorage = this.storage,
        transferService: PasswordTransferService = FakeTransfer(),
    ) = LocalPasswordRepository(
        userPreferences = prefs,
        coroutinesContextFacade = UnconfinedFacade,
        vaultCipher = vaultCipher,
        storage = storage,
        transferService = transferService,
        entryIdentity = identity,
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

    /**
     * A migrated, settled suite-5 vault holding [names] in name order at ordinals `1..N`.
     *
     * Settling matters: an unmigrated vault would send the first read down the migration branch and
     * the concurrency tests would be racing something other than what they claim to.
     */
    private fun settledVault(vararg names: String) = runBlocking {
        legacyVault(names.mapIndexed { index, name -> entry(name, id = (index + 1).toString(), dateCreated = 1_000L + index) })
        assertEquals(names.toList(), repository().getPasswordEntries().map { it.entryName })
    }

    /**
     * `[gmail/alice, gmail/bob, zoom/z]`, migrated and settled.
     *
     * Two rows sharing a name and differing only in username: the shape nothing in the product
     * prevents, nothing in this file used to cover, and every uuid-keyed mutation used to act on
     * twice over. `zoom/z` is the bystander that separates "the twins were mishandled" from "the
     * vault was emptied".
     */
    private fun namesakeVault() = runBlocking {
        legacyVault(
            listOf(
                entry("gmail", id = "1", dateCreated = 1_000L, username = "alice"),
                entry("gmail", id = "2", dateCreated = 1_001L, username = "bob"),
                entry("zoom", id = "3", dateCreated = 1_002L, username = "z"),
            ),
        )
        assertEquals(listOf("alice", "bob", "z"), repository().getPasswordEntries().map { it.username })
    }

    private fun storedEntries(): List<PasswordEntry> =
        Json.decodeFromString(vaultCipher.decryptVault(storage.read(user), sessionKey) { null }.plaintext.decodeToString())

    private fun entry(
        name: String,
        id: String = "1",
        dateCreated: Long = 1_000L,
        password: String = "p-$name",
        username: String = "u-$name",
    ) = PasswordEntry(
        id = id,
        dateCreated = dateCreated,
        entryName = name,
        password = password,
        website = "https://$name",
        username = username,
        notes = "n-$name",
    )

    private fun entryData(name: String, userName: String = "u-$name") = AddPassword.EntryData(
        entryName = name,
        userName = userName,
        password = "p-$name",
        website = "https://$name",
        notes = "n-$name",
    )

    private suspend fun vaultSession(): VaultSession = KoinPlatform.getKoin()
        .getOrCreateScope("session-${prefs.getSessionId()}", named("sessionScope"))
        .get(named(VAULT_SESSION_HANDLE))

    // ---------------------------------------------------------------- fakes

    /**
     * Real storage with the first read held open, so a second caller can overtake the first.
     *
     * A decorator on the production storage rather than a fake: what is under test is the
     * interaction between the repository's retry and the store's compare-and-set, and a fake would
     * only prove the fake agrees with itself.
     */
    private class ParkingStorage(
        private val delegate: PasswordDatabaseStorage,
        private val reached: CountDownLatch,
        private val release: CountDownLatch,
    ) : PasswordDatabaseStorage by delegate {
        private val armed = AtomicBoolean(true)

        override fun read(username: String): ByteArray {
            // Answer first, then park: the point is to resume holding a *stale* answer.
            val answer = delegate.read(username)
            if (armed.compareAndSet(true, false)) {
                reached.countDown()
                check(release.await(PARK_TIMEOUT_SECONDS, TimeUnit.SECONDS)) { "the parked caller was never released" }
            }
            return answer
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

    /** Publishes nothing. `replaceIfUnchanged` is defined in terms of `write`, so both fail together. */
    private class FailingStorage(private val delegate: PasswordDatabaseStorage) :
        PasswordDatabaseStorage by delegate {
        override fun write(username: String, encryptedBytes: ByteArray): Unit =
            throw java.io.IOException("simulated write failure")

        override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean =
            throw java.io.IOException("simulated write failure")
    }

    private class FakeTransfer(private val pullBytes: ByteArray = ByteArray(0)) : PasswordTransferService {
        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            hostName: String,
            port: Int,
        ) = Outcome.Success(Unit)

        override suspend fun transferDatabaseBytes(
            decryptedDatabaseBytes: ByteArray,
            fileName: String,
            device: TrustedDevice,
            port: Int,
        ) = Outcome.Success(Unit)

        override suspend fun pullDatabase(device: TrustedDevice, port: Int) = Outcome.Success(pullBytes)
    }

    private class FakePreferences : UserPreferences {
        override suspend fun getUser(): AppUser = AppUser.LoggedIn("alice", Password("h", "s"))
        override suspend fun upsert(user: AppUser) = Unit
        override suspend fun getStoredCredentials(username: String): Password? = null
        override suspend fun getUserState(): UserState? = null
        override suspend fun setUserState(state: UserState) = Unit
        override suspend fun getSessionId(): String = "entry-identity-test"
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
