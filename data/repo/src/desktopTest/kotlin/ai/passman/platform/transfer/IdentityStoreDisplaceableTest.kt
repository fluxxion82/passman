package ai.passman.platform.transfer

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Whether `syncExclusions` is strong enough to prove that `unbundle` can never touch the identity
 * store — the claim the shared-writer-lock design was about to rest on.
 *
 * The argument under test ran: everything `IdentityStoreLock` guards is in
 * [DirectoryBundler.syncExclusions], `unbundle` skips excluded basenames before staging them, so the
 * two locks guard disjoint files and no site ever needs both. If that held, the identity-store paths
 * would need no artifact-directory lock and there would be no lock ordering to get wrong.
 *
 * It does not hold. The exclusion is a **string comparison on a basename**; which file a path names
 * is decided by the **filesystem**. Wherever those two disagree, an inbound entry slips past the
 * exclusion and lands on the live identity store anyway — displaced by `preserveDisplaced` and
 * replaced by `DurableFiles.replace`, neither of which holds `IdentityStoreLock`.
 *
 * These tests are written to **pass**, because they assert the bypass that is really there. Each
 * carries, in its comments, the assertion that would hold if the exclusion did what the design
 * assumed, so the day the underlying defect is fixed they fail loudly and get rewritten rather than
 * quietly going green for a new reason.
 *
 * ## What has since changed, and what has not
 *
 * `ValidateSignUpCredentials` now refuses a username that is really a path, and `SignUpUser` — the
 * use case that owns account creation — enforces it rather than leaving it to the sign-up screen, so
 * **a new account can no longer be created with any of these names**. That closes the route in, and
 * it is why the fix went there rather than into another guard. (This sentence was false for one
 * commit, while the check lived only in `SignUpViewModel`.)
 *
 * The mechanism these tests describe is untouched: `syncExclusions` still compares basename strings
 * where the filesystem resolves paths. An account created before the rule existed still has a name
 * like these, and the bypass still applies to it. So these keep documenting a real property of
 * `unbundle` — they simply construct the account directly instead of through sign-up, which is now
 * the only way to reach it.
 */
class IdentityStoreDisplaceableTest {
    private lateinit var tempDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("identity-store-displaceable-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    /**
     * A username carrying path syntax defeats the exclusion, and sync replaces the identity store.
     *
     * `./alice` was an acceptable account name when this was written: the username was gated on
     * length alone. Sign-up refuses it now, so this fixture builds the account directly — the point
     * is what `unbundle` does with such a directory, which is unchanged and still applies to any
     * account created before that rule. Every path in the app builds from the username by string
     * concatenation:
     *
     * - the account directory is `keystore/./alice`, which the filesystem resolves to `keystore/alice`;
     * - `JvmKeystoreLifecycle.keystoreFileName` makes the store `./alice.pfx` inside it, which
     *   resolves to `keystore/alice/alice.pfx`;
     * - `syncExclusions("./alice")` therefore contains the string `"./alice.pfx"`.
     *
     * But `unbundle` matches its exclusion set against `File(entry).name`, a **basename**. A peer
     * sending the perfectly ordinary entry `alice.pfx` produces the basename `alice.pfx`, which is
     * not equal to `./alice.pfx`, so the entry is not skipped — and `File(destDir, "alice.pfx")`
     * resolves to exactly the inode the identity store lives at.
     *
     * No hostile peer is required: `alice.pfx` is what an ordinary peer's own bundle carries when its
     * outbound exclusion misses the file for the same reason.
     */
    @Test
    fun pathSyntaxInAUsernameLetsSyncReplaceTheIdentityStore() {
        val user = "./alice"
        val exclusions = DirectoryBundler.syncExclusions(user)

        // The exclusion set is built from the raw username, so it holds a path, not a basename.
        assertTrue(
            "./alice.pfx" in exclusions,
            "precondition: the exclusion set carries the username verbatim",
        )
        assertTrue(
            "alice.pfx" !in exclusions,
            "precondition: and therefore NOT the basename the filesystem resolves to",
        )

        val destDir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        // Where JvmKeyStoreClient actually writes: File(folder, "./alice.pfx") under the folder
        // "keystore/./alice". Both sides resolve to keystore/alice/alice.pfx.
        val identityStore = File(destDir, "$user.pfx")
        identityStore.writeBytes(LOCAL_IDENTITY)
        assertEquals(
            File(tempDir, "keystore${File.separator}alice${File.separator}alice.pfx").canonicalPath,
            identityStore.canonicalPath,
            "precondition: the store the writer creates and the path a peer's entry names are one file",
        )

        DirectoryBundler.unbundle(zipOf("alice.pfx" to PEER_BYTES), destDir, excludeBaseNames = exclusions)

        // What the design assumed, kept as the assertion that must start passing once the exclusion
        // is made resolution-aware:
        //     assertContentEquals(LOCAL_IDENTITY, identityStore.readBytes())
        assertContentEquals(
            PEER_BYTES,
            identityStore.readBytes(),
            "the identity store was replaced by an inbound sync entry, with no IdentityStoreLock held",
        )
        // It was preserved rather than destroyed — the guard from the previous branch did its job.
        // That is the only reason this is a lock-scope defect and not outright key loss.
        val preserved = DirectoryBundler.preservedCopies(destDir)
        assertEquals(1, preserved.size, "the displaced identity store belongs in the conflict store")
        assertContentEquals(LOCAL_IDENTITY, preserved.single().readBytes())
    }

    /**
     * The control for the test above, and the whole reason it means anything.
     *
     * Identical in every respect except that the username carries no path syntax. Here the exclusion
     * does what the design assumed: the entry is skipped, the identity store keeps its bytes, and
     * nothing reaches the conflict store. The difference in outcome between these two tests is
     * therefore attributable to the username's spelling and to nothing else — not to an empty
     * exclusion set, not to a misnamed entry, not to the store sitting somewhere the unbundle was
     * never going to look.
     */
    @Test
    fun controlAPlainUsernameIsExcludedAndTheIdentityStoreSurvives() {
        val user = "alice"
        val exclusions = DirectoryBundler.syncExclusions(user)
        assertTrue("alice.pfx" in exclusions)

        val destDir = File(tempDir, "keystore${File.separator}$user").apply { mkdirs() }
        val identityStore = File(destDir, "$user.pfx")
        identityStore.writeBytes(LOCAL_IDENTITY)

        DirectoryBundler.unbundle(zipOf("alice.pfx" to PEER_BYTES), destDir, excludeBaseNames = exclusions)

        assertContentEquals(
            LOCAL_IDENTITY,
            identityStore.readBytes(),
            "with an ordinary username the exclusion holds and sync leaves the identity store alone",
        )
        assertTrue(
            DirectoryBundler.preservedCopies(destDir).isEmpty(),
            "an excluded entry is skipped before staging, so nothing is ever displaced",
        )
    }

    /**
     * Why the bypass above is a general property of the mechanism, not one odd username.
     *
     * The exclusion set is built by string concatenation from the stored username and compared by
     * string equality, so it can only ever exclude the **one spelling it was built from**. Case is
     * the single divergence `unbundle` handles, by folding both sides. Nothing folds Unicode
     * normalisation — searching the tree for `Normalizer` / `normalize(` finds no production use —
     * yet APFS and NTFS both resolve the two normal forms of a name to one file.
     *
     * So on macOS, which the desktop app ships for, an account whose name contains any decomposable
     * character has an identity store reachable under a spelling its own exclusion set does not
     * contain. Sign-up now refuses non-ASCII usernames for exactly this reason, which is what closes
     * the route in; the set-level property asserted here is about `syncExclusions` itself and is
     * unchanged.
     *
     * Asserted at the set level rather than against the filesystem, so it states the same fact on
     * every platform instead of passing for a filesystem-specific reason on one and being vacuous on
     * another. The NFD form is spelled with an escape so the source cannot be silently re-normalised
     * by an editor into the NFC one, which would make the test pass while comparing a string to
     * itself.
     */
    @Test
    fun theExclusionSetOnlyEverMatchesTheOneSpellingItWasBuiltFrom() {
        val precomposed = "caf\u00E9" // NFC: c a f LATIN SMALL LETTER E WITH ACUTE
        val decomposed = "cafe\u0301" // NFD: c a f e COMBINING ACUTE ACCENT
        assertEquals(
            precomposed.length + 1,
            decomposed.length,
            "precondition: two spellings of one name, not one string written twice",
        )

        val exclusions = DirectoryBundler.syncExclusions(precomposed)
        assertTrue("$precomposed.pfx" in exclusions, "precondition: the stored spelling is excluded")
        assertTrue(
            "$decomposed.pfx" !in exclusions,
            "the other normal form is not, though a normalisation-insensitive filesystem resolves " +
                "both to the same identity store",
        )
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private companion object {
        val LOCAL_IDENTITY = ByteArray(64) { 0x11 }
        val PEER_BYTES = ByteArray(64) { 0x22 }
    }
}
