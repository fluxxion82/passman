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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The invariant, as executable requirements:
 *
 * > Sync never destroys key material, and every non-obvious action is visible and reversible.
 *
 * `unbundle` merges by basename, so it cannot tell "same artifact, newer bytes" from "different
 * artifact, same name". It therefore may never *replace* anything without first putting the bytes it
 * is displacing somewhere the user can still get at them. On the PGP side the bytes in question are
 * secret rings, and a lost one is a private key that exists nowhere else.
 *
 * See `docs/plans/2026-08-21-sync-never-destroys-key-material-plan.md`.
 */
class UnbundlePreservesKeyMaterialTest {

    private lateinit var root: File
    private lateinit var destDir: File

    @BeforeTest
    fun setUp() {
        root = Files.createTempDirectory("unbundle-preserve-test").toFile()
        destDir = File(root, "alice").apply { mkdirs() }
    }

    @AfterTest
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun `a differing inbound file does not destroy the local one`() {
        val local = File(destDir, "work_secret_ring.asc").apply { writeBytes(LOCAL) }

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        assertContentEquals(INBOUND, local.readBytes(), "the inbound copy should be live")
        assertContentEquals(
            LOCAL,
            preservedBytes().single(),
            "the displaced local bytes must survive somewhere reachable",
        )
    }

    @Test
    fun `an identical inbound file changes nothing`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to LOCAL), destDir)

        assertTrue(
            preservedBytes().isEmpty(),
            "identical bytes are not a conflict; preserving them would fill the store with noise",
        )
    }

    @Test
    fun `a file the device does not have yet is simply written`() {
        DirectoryBundler.unbundle(zipOf("new_secret_ring.asc" to INBOUND), destDir)

        assertContentEquals(INBOUND, File(destDir, "new_secret_ring.asc").readBytes())
        assertTrue(preservedBytes().isEmpty(), "a new file displaces nothing")
    }

    @Test
    fun `preserved copies live outside the directory that gets bundled`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        // The whole reason the conflict store is a SIBLING: bundle() walks every descendant of
        // destDir, so a preserved secret ring inside it would be shipped to the peer on the next
        // push — turning a local safety copy into a key-material leak.
        val outbound = entryNames(DirectoryBundler.bundle(destDir))

        assertEquals(setOf("work_secret_ring.asc"), outbound)
    }

    @Test
    fun `preserving the same bytes twice yields one copy`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        val bundle = zipOf("work_secret_ring.asc" to INBOUND)

        DirectoryBundler.unbundle(bundle, destDir)
        // A second application of the same bundle: the live file already matches, so this is the
        // bytes-equal no-op path and must not preserve anything further.
        DirectoryBundler.unbundle(bundle, destDir)

        assertEquals(1, preservedBytes().size, "re-applying a bundle must not pile up copies")
    }

    @Test
    fun `two different displaced versions are both kept`() {
        val first = ByteArray(96) { 7 }
        val second = ByteArray(96) { 8 }
        File(destDir, "work_secret_ring.asc").writeBytes(first)

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to second), destDir)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        val preserved = preservedBytes()
        assertEquals(2, preserved.size, "each distinct displaced version is someone's only copy")
        assertTrue(preserved.any { it.contentEquals(first) })
        assertTrue(preserved.any { it.contentEquals(second) })
    }

    @Test
    fun `an unreadable local file is preserved rather than destroyed`() {
        // Safety must never be gated on being able to parse the thing. BouncyCastle silently drops
        // subkeys it does not understand, so "cannot read it" is a state real key material reaches.
        val garbage = ByteArray(64) { 0xEF.toByte() }
        File(destDir, "work_secret_ring.asc").writeBytes(garbage)

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        assertContentEquals(garbage, preservedBytes().single())
    }

    @Test
    fun `a rejected bundle preserves nothing, because it displaced nothing`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        val oversized = zipOf("work_secret_ring.asc" to ByteArray(4_096))

        runCatching { DirectoryBundler.unbundle(oversized, destDir, maxTotalBytes = 1_024) }

        assertContentEquals(LOCAL, File(destDir, "work_secret_ring.asc").readBytes())
        assertTrue(
            preservedBytes().isEmpty(),
            "a bundle that never committed must not leave conflict-store residue",
        )
    }

    /**
     * The property the whole design rests on, and the one an end-to-end test cannot see: preserving
     * must MOVE the live file, not copy it.
     *
     * A copy preserves the bytes as they were when it read them. Push-receive is a background server
     * and key edits are foreground UI — `addSubKey` and `changeKeyPassword` rewrite the live path
     * directly — so a write landing between "copy the old bytes" and "replace with the peer's" is
     * discarded, and the copy in the store holds the version from *before* that write. The private
     * half of a subkey added in that window would exist nowhere.
     *
     * Vacating the live path is what makes that impossible to express. Asserted directly rather than
     * by racing threads, because a timing test that passes is not evidence of anything.
     */
    @Test
    fun `preserving moves the live file rather than copying it`() {
        val live = File(destDir, "work_secret_ring.asc").apply { writeBytes(LOCAL) }
        val liveKey = java.nio.file.Files.readAttributes(live.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        // The preserved copy is the SAME inode the live file had — it was moved, not copied. A copy
        // would leave the original bytes at the live path to be overwritten by the commit, which is
        // how a write landing in between gets silently discarded.
        val preserved = DirectoryBundler.preservedCopies(destDir).single()
        val preservedKey = java.nio.file.Files.readAttributes(preserved.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java).fileKey()
        assertEquals(liveKey, preservedKey, "the displaced file must be moved into the store, not copied")
    }

    @Test
    fun `an unchanged file is not rewritten at all`() {
        val live = File(destDir, "work_secret_ring.asc").apply { writeBytes(LOCAL) }
        live.setLastModified(1_000_000_000L)

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to LOCAL), destDir)

        // Not merely "nothing preserved": nothing WRITTEN. Rewriting a file with its own bytes
        // reopens the window this whole design closes — a foreground write landing between the
        // comparison and the replace would be overwritten, and the preserve would have found
        // nothing displaced to save.
        assertEquals(1_000_000_000L, live.lastModified(), "an unchanged file must not be rewritten")
    }

    @Test
    fun `the digest is taken from the displaced bytes, not the incoming ones`() {
        // Displace A with X, put B live, then receive X again. If the name were derived from the
        // INCOMING bytes both preserves would land on one name — and the second would destroy the
        // first, which is this whole class of bug one directory along.
        val versionA = ByteArray(80) { 3 }
        val versionB = ByteArray(80) { 4 }
        val incoming = ByteArray(80) { 9 }

        File(destDir, "work_secret_ring.asc").writeBytes(versionA)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to incoming), destDir)
        File(destDir, "work_secret_ring.asc").writeBytes(versionB)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to incoming), destDir)

        val preserved = preservedBytes()
        assertEquals(2, preserved.size, "both displaced versions are somebody's only copy")
        assertTrue(preserved.any { it.contentEquals(versionA) })
        assertTrue(preserved.any { it.contentEquals(versionB) })
    }

    @Test
    fun `a nested entry preserves outside the bundled tree`() {
        // The peer authors entry names, so nested paths are reachable. Deriving the store from the
        // live file's own parent would put it at destDir/sub.conflicts — a CHILD, which the next
        // outbound bundle ships to every peer.
        val nested = File(destDir, "sub").apply { mkdirs() }
        File(nested, "work_secret_ring.asc").writeBytes(LOCAL)

        DirectoryBundler.unbundle(zipOf("sub/work_secret_ring.asc" to INBOUND), destDir)

        assertContentEquals(LOCAL, preservedBytes().single(), "nested preserves must reach the store")
        assertEquals(
            setOf("sub/work_secret_ring.asc"),
            entryNames(DirectoryBundler.bundle(destDir)),
            "no preserved copy may appear in an outbound bundle",
        )
        assertEquals(
            "sub/work_secret_ring.asc",
            DirectoryBundler.originalPathOf(DirectoryBundler.preservedCopies(destDir).single()),
            "restore has to put a copy back where it came from, so the path must round-trip",
        )
    }

    @Test
    fun `an original path survives characters that collide with the escape`() {
        // A path containing the escape sequence itself must not decode into a different path — the
        // difference between restoring a file and creating a directory that was never there.
        val awkward = "od%2Fd name.asc"
        File(destDir, awkward).writeBytes(LOCAL)

        DirectoryBundler.unbundle(zipOf(awkward to INBOUND), destDir)

        assertEquals(awkward, DirectoryBundler.originalPathOf(DirectoryBundler.preservedCopies(destDir).single()))
    }

    @Test
    fun `a hand-copied file in the store still reports something`() {
        // The store is a plain directory, so a user may put a file in it. Showing its name beats
        // inventing a path, and beats hiding a file that may be someone's only copy.
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)
        val strange = File(DirectoryBundler.conflictStore(destDir), "rescued-by-hand.asc")
        strange.writeBytes(ByteArray(4))

        assertEquals("rescued-by-hand.asc", DirectoryBundler.originalPathOf(strange))
        assertEquals(2, DirectoryBundler.preservedCopies(destDir).size, "a hand-placed file must still be listed")
    }

    @Test
    fun `a deeply nested entry still preserves`() {
        // A nested entry flattens its entire path into one conflict filename, so components that are
        // each legal can still overflow the filesystem's limit. That threw from the rename — failing
        // safe for the live file, but aborting the unbundle mid-commit, and aborting again on every
        // later sync of that path. A peer could wedge a directory's sync for good.
        val deep = (1..8).joinToString("/") { "component-$it-" + "x".repeat(28) } + "/secret_ring.asc"

        DirectoryBundler.unbundle(zipOf(deep to LOCAL), destDir)
        DirectoryBundler.unbundle(zipOf(deep to INBOUND), destDir)

        assertContentEquals(INBOUND, File(destDir, deep).readBytes())
        assertContentEquals(LOCAL, preservedBytes().single())
        assertTrue(
            DirectoryBundler.preservedCopies(destDir).single().name.toByteArray().size <= 255,
            "a conflict filename must fit what the filesystem accepts",
        )
    }

    @Test
    fun `bilateral sync ping-pong keeps every version`() {
        // Two devices trading versions reaches a state that had no coverage: the live file matches a
        // copy already in the store. That is the branch where the preserve dedupes, and it used to
        // do so by deleting the live path outright — an action decided from an earlier read, so a
        // key edit landing in between was deleted having never been preserved. The preserve now
        // captures by rename first and only ever deletes a file inside the store.
        val v0 = ByteArray(64) { 10 }
        val v1 = ByteArray(64) { 11 }
        val v2 = ByteArray(64) { 12 }
        File(destDir, "work_secret_ring.asc").writeBytes(v0)

        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to v1), destDir)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to v0), destDir)
        // Live is v0 again, and v0 is already in the store: the dedupe branch.
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to v2), destDir)

        assertContentEquals(v2, File(destDir, "work_secret_ring.asc").readBytes())
        val preserved = preservedBytes()
        assertTrue(preserved.any { it.contentEquals(v0) }, "v0 must still be recoverable")
        assertTrue(preserved.any { it.contentEquals(v1) }, "v1 must still be recoverable")
        assertEquals(2, preserved.size, "dedupe must not pile up copies of a version already stored")
    }

    @Test
    fun `a capture never leaves the live path deleted without a copy`() {
        // The store is where a displaced version goes, so an unwritable store must stop the preserve
        // before the live file is touched, not after. Fails toward keeping bytes.
        val live = File(destDir, "work_secret_ring.asc").apply { writeBytes(LOCAL) }
        val store = DirectoryBundler.conflictStore(destDir)
        // A regular file where the store directory belongs: mkdirs cannot succeed.
        store.parentFile.mkdirs()
        store.writeBytes(ByteArray(1))

        runCatching { DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir) }

        assertContentEquals(
            LOCAL,
            live.readBytes(),
            "if the displaced bytes cannot be stored, the live file must be left alone",
        )
    }

    @Test
    fun `restoring puts the copy back and preserves what it replaces`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        val restored = DirectoryBundler.restorePreserved(DirectoryBundler.preservedCopies(destDir).single(), destDir)

        assertTrue(restored)
        assertContentEquals(LOCAL, File(destDir, "work_secret_ring.asc").readBytes(), "the copy must be live again")
        assertContentEquals(
            INBOUND,
            preservedBytes().single(),
            "undoing a sync must not destroy the version the sync installed",
        )
    }

    @Test
    fun `restoring a nested copy goes back to its own directory`() {
        File(destDir, "sub").mkdirs()
        File(destDir, "sub/work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("sub/work_secret_ring.asc" to INBOUND), destDir)

        assertTrue(DirectoryBundler.restorePreserved(DirectoryBundler.preservedCopies(destDir).single(), destDir))

        assertContentEquals(LOCAL, File(destDir, "sub/work_secret_ring.asc").readBytes())
    }

    @Test
    fun `restoring leaves the store when the copy is already live`() {
        // Restoring something byte-identical to the live file is a no-op for the artifact, but the
        // copy has to stop being listed or the user restores forever. It must go by the same
        // capture-and-dedupe path, not by reading the live file and deciding.
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)
        val copy = DirectoryBundler.preservedCopies(destDir).single()
        DirectoryBundler.restorePreserved(copy, destDir)

        // Live is LOCAL again and the store holds INBOUND. Restore LOCAL a second time.
        val again = DirectoryBundler.restorePreserved(
            DirectoryBundler.preservedCopies(destDir).first { it.readBytes().contentEquals(INBOUND) },
            destDir,
        )

        assertTrue(again)
        assertContentEquals(INBOUND, File(destDir, "work_secret_ring.asc").readBytes())
        assertEquals(1, preservedBytes().size, "each restore swaps live and stored, never accumulates")
    }

    @Test
    fun `a copy whose name escapes the artifact directory is not restored`() {
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)
        // The store is a plain directory and a user can rename things in it. A name that decodes to
        // an escaping path must be refused, not written outside the artifact directory.
        val hostile = File(DirectoryBundler.conflictStore(destDir), "${"a".repeat(32)}-..%2Fescaped.asc")
        hostile.writeBytes(LOCAL)

        assertFalse(DirectoryBundler.restorePreserved(hostile, destDir))
        // Escaping one level lands inside this test's own root, which tearDown removes. Reaching
        // further would write into the shared system temp directory and outlive the test — which is
        // exactly what happened while mutation-checking this assertion, and it then poisoned every
        // later run. A test for an escape must not be able to escape.
        assertFalse(File(root, "escaped.asc").exists(), "restore must not write outside the artifact directory")
    }

    @Test
    fun `a copy whose path did not fit is not restored to a guessed one`() {
        // The name budget truncates a path that will not fit a filename. Decoding that truncation
        // and treating it as a destination is the trap: it looks like a successful restore, but the
        // copy lands at a filename that never existed while the artifact it was meant to replace
        // sits there unchanged. Refusing is the honest answer; the bytes stay exportable.
        val deep = (1..8).joinToString("/") { "component-$it-" + "x".repeat(28) } + "/secret_ring.asc"
        DirectoryBundler.unbundle(zipOf(deep to LOCAL), destDir)
        DirectoryBundler.unbundle(zipOf(deep to INBOUND), destDir)
        val copy = DirectoryBundler.preservedCopies(destDir).single()

        assertFalse(DirectoryBundler.hasRecoverablePath(copy), "this path cannot fit a filename")
        assertFalse(DirectoryBundler.restorePreserved(copy, destDir))

        assertContentEquals(INBOUND, File(destDir, deep).readBytes(), "the live artifact is untouched")
        assertEquals(1, preservedBytes().size, "and the copy stays put, still exportable")
    }

    @Test
    fun `a path that fits is still restorable`() {
        // Guard against the refusal above being over-eager: ordinary names must keep working.
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)

        assertTrue(DirectoryBundler.hasRecoverablePath(DirectoryBundler.preservedCopies(destDir).single()))
    }

    @Test
    fun `a store file whose name does not parse is never restored into the artifact directory`() {
        // originalPathOf falls back to the whole filename so hand-placed files still list. Restore
        // must not consume that fallback as a destination: the file would land in the artifact
        // directory under a store-ish name, which no listing reads and which the NEXT OUTBOUND
        // BUNDLE would ship to every peer — walking preserved key material straight back into the
        // syncable tree the sibling store exists to keep it out of.
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)
        val handPlaced = File(DirectoryBundler.conflictStore(destDir), "rescued-by-hand.asc")
        handPlaced.writeBytes(ByteArray(8) { 5 })

        assertFalse(DirectoryBundler.restorePreserved(handPlaced, destDir))

        assertTrue(handPlaced.isFile, "and it stays put, still exportable")
        assertEquals(
            setOf("work_secret_ring.asc"),
            entryNames(DirectoryBundler.bundle(destDir)),
            "nothing from the store may reach an outbound bundle",
        )
    }

    @Test
    fun `a failed restore leaves a file at the artifact path`() {
        // Restore vacates the live path before installing. If the install then fails, the artifact
        // directory must not be left with nothing at that path — no ring at all is a worse place to
        // land than the version the user was trying to replace.
        File(destDir, "work_secret_ring.asc").writeBytes(LOCAL)
        DirectoryBundler.unbundle(zipOf("work_secret_ring.asc" to INBOUND), destDir)
        val copy = DirectoryBundler.preservedCopies(destDir).single()
        // A non-empty directory at the target: the install's rename cannot complete onto it.
        File(destDir, "work_secret_ring.asc").delete()
        File(destDir, "work_secret_ring.asc").mkdirs()
        File(destDir, "work_secret_ring.asc/occupied").writeBytes(ByteArray(4))

        runCatching { DirectoryBundler.restorePreserved(copy, destDir) }

        assertTrue(File(destDir, "work_secret_ring.asc").exists(), "the artifact path must not be vacated")
        assertTrue(copy.isFile, "and the copy must still be recoverable")
    }

    // ---- helpers ---------------------------------------------------------------------------

    /** Every preserved copy for [destDir], whatever the conflict store chooses to name them. */
    private fun preservedBytes(): List<ByteArray> =
        DirectoryBundler.preservedCopies(destDir).map { it.readBytes() }

    private fun entryNames(bundle: ByteArray): Set<String> {
        val names = mutableSetOf<String>()
        java.util.zip.ZipInputStream(bundle.inputStream()).use { zip ->
            var entry = zip.nextEntry
            while (entry != null) {
                names += entry.name
                entry = zip.nextEntry
            }
        }
        return names
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private companion object {
        val LOCAL = ByteArray(128) { 1 }
        val INBOUND = ByteArray(128) { 2 }
    }
}
