package ai.passman.platform.transfer

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
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
