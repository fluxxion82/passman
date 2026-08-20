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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * DoS-hardening regression tests for [DirectoryBundler.unbundle]: entry-count cap, uncompressed
 * total-bytes cap (zip-bomb), and path-traversal / escape confinement.
 */
class DirectoryBundlerDosTest {
    private lateinit var destDir: File

    @BeforeTest
    fun setUp() {
        destDir = Files.createTempDirectory("bundler-dos-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        destDir.deleteRecursively()
    }

    private fun zipOf(entries: List<Pair<String, ByteArray>>): ByteArray {
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

    @Test
    fun aRejectedBundleLeavesNothingBehind() {
        // The caps throw from inside an open output stream, so writing straight to the final paths
        // left earlier entries committed and the current one truncated. A caller that treats the
        // throw as "push rejected" would then be wrong about what is on disk.
        val bundle = zipOf(
            listOf(
                "good.asc" to ByteArray(512) { 1 },
                "big.bin" to ByteArray(4_096) { 0 },
            ),
        )

        assertFailsWith<DirectoryBundler.BundleTooLargeException> {
            DirectoryBundler.unbundle(bundle, destDir, maxTotalBytes = 1_024)
        }

        assertFalse(
            File(destDir, "good.asc").exists(),
            "an entry from a bundle that failed validation must not survive in the destination",
        )
        assertFalse(File(destDir, "big.bin").exists(), "the truncated entry must not survive either")
    }

    @Test
    fun aRejectedBundleDoesNotDamageWhatWasAlreadyThere() {
        val existing = File(destDir, "good.asc").apply { writeBytes(ByteArray(64) { 7 }) }
        val bundle = zipOf(
            listOf(
                "good.asc" to ByteArray(512) { 1 },
                "big.bin" to ByteArray(4_096) { 0 },
            ),
        )

        assertFailsWith<DirectoryBundler.BundleTooLargeException> {
            DirectoryBundler.unbundle(bundle, destDir, maxTotalBytes = 1_024)
        }

        // The pre-existing key file is what a failed sync used to overwrite with a prefix of the
        // peer's copy. A truncated ring is skipped by the key listing without a word, so the key
        // would simply have vanished.
        assertContentEquals(ByteArray(64) { 7 }, existing.readBytes())
    }

    @Test
    fun stagingIsNotLeftBesideTheDestination() {
        val bundle = zipOf(listOf("a.asc" to ByteArray(8) { 3 }))

        DirectoryBundler.unbundle(bundle, destDir)

        // Staging is a sibling of destDir, so a leaked one would sit next to the artifact directory
        // and, worse, be a candidate for the next outbound bundle of the parent.
        val siblings = destDir.parentFile.listFiles().orEmpty().map { it.name }
        assertFalse(
            siblings.any { it.startsWith(destDir.name) && it != destDir.name },
            "no staging directory may remain: $siblings",
        )
        assertContentEquals(ByteArray(8) { 3 }, File(destDir, "a.asc").readBytes())
    }

    @Test
    fun tooManyEntriesRejected() {
        val bundle = zipOf((0 until 5).map { "file-$it.txt" to byteArrayOf(1) })
        assertFailsWith<DirectoryBundler.BundleTooLargeException> {
            DirectoryBundler.unbundle(bundle, destDir, maxEntries = 3)
        }
    }

    @Test
    fun oversizedUncompressedRejected() {
        val big = ByteArray(4_096) { 0 } // highly compressible -> tiny zip, large expansion
        val bundle = zipOf(listOf("big.bin" to big))
        assertFailsWith<DirectoryBundler.BundleTooLargeException> {
            DirectoryBundler.unbundle(bundle, destDir, maxTotalBytes = 1_024)
        }
    }

    @Test
    fun pathTraversalEntrySkippedNotWritten() {
        val bundle = zipOf(listOf("../escaped.txt" to byteArrayOf(9)))
        DirectoryBundler.unbundle(bundle, destDir)
        assertFalse(File(destDir.parentFile, "escaped.txt").exists(), "traversal entry must not escape destDir")
    }

    @Test
    fun normalBundleRoundTripsWithinCaps() {
        val bundle = zipOf(listOf("a.txt" to "hello".toByteArray(), "sub/b.txt" to "world".toByteArray()))
        DirectoryBundler.unbundle(bundle, destDir)
        assertTrue(File(destDir, "a.txt").exists())
        assertEquals("hello", File(destDir, "a.txt").readText())
        assertEquals("world", File(destDir, "sub/b.txt").readText())
    }
}
