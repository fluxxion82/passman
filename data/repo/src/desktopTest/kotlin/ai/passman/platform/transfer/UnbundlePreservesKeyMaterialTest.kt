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
        val incoming = File(root, "staged").apply { writeBytes(INBOUND) }

        DirectoryBundler.preserveIfDisplaced(live, incoming)

        assertFalse(
            live.exists(),
            "the live path must be vacated by the preserve; if it still holds bytes, they were " +
                "copied and a concurrent write to it would be silently discarded by the commit",
        )
        assertContentEquals(LOCAL, preservedBytes().single())
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
