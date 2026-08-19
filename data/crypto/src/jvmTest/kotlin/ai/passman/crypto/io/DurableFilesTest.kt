package ai.passman.crypto.io

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What is actually testable here, and what is not.
 *
 * The bug this replaced was Windows-specific: `File.renameTo` fails onto an existing destination
 * there, so `if (!tmp.renameTo(target)) { target.delete(); tmp.renameTo(target) }` took the
 * delete-then-rename branch as its normal path and left a window with no copy under either name. A
 * POSIX test host cannot observe that at all — `renameTo` simply succeeds — so no assertion below
 * distinguishes the old code from the new one on this machine. These tests pin the contract that
 * makes the Windows path safe (replace an existing target in one call; leave the source alone and
 * the target intact when the move cannot happen) rather than pretending to reproduce the platform.
 */
class DurableFilesTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("durable-files").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    @Test
    fun `replace overwrites an existing target and consumes the source`() {
        val target = File(dir, "target").apply { writeText("old") }
        val source = File(dir, "source").apply { writeText("new") }

        DurableFiles.replace(source, target)

        assertContentEquals("new".encodeToByteArray(), target.readBytes())
        assertFalse(source.exists(), "the source must be consumed, not copied")
    }

    @Test
    fun `replace creates a target that does not exist yet`() {
        val target = File(dir, "target")
        val source = File(dir, "source").apply { writeText("fresh") }

        DurableFiles.replace(source, target)

        assertEquals("fresh", target.readText())
    }

    /** A failed move must leave both files exactly as they were; the caller still holds the source. */
    @Test
    fun `replace leaves the target intact when the source is missing`() {
        val target = File(dir, "target").apply { writeText("keep me") }
        val source = File(dir, "never-written")

        assertFailsWith<java.nio.file.NoSuchFileException> { DurableFiles.replace(source, target) }

        assertEquals("keep me", target.readText())
    }

    /** Best-effort by contract: it must never throw, whatever the platform makes of a directory. */
    @Test
    fun `syncDirectory tolerates a null, a missing directory and a plain file`() {
        DurableFiles.syncDirectory(null)
        DurableFiles.syncDirectory(File(dir, "no-such-directory"))
        DurableFiles.syncDirectory(File(dir, "a-file").apply { writeText("x") })
        DurableFiles.syncDirectory(dir)
        assertTrue(dir.isDirectory)
    }
}
