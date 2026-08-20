package ai.passman

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InstanceLockTest {

    private lateinit var dataDir: File

    @BeforeTest
    fun setUp() {
        dataDir = Files.createTempDirectory("instance-lock-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        dataDir.deleteRecursively()
    }

    @Test
    fun `the first claim on a data directory succeeds`() {
        assertTrue(InstanceLock().claim(dataDir))
    }

    @Test
    fun `a second claim on the same data directory is refused`() {
        val first = InstanceLock()
        assertTrue(first.claim(dataDir), "precondition: the first claim must succeed")

        assertFalse(
            InstanceLock().claim(dataDir),
            "a second instance pointed at the same profile must be refused - both would bind the " +
                "sync listener on the same port, and the loser reports 'address already in use'",
        )
    }

    @Test
    fun `a different data directory is a different claim`() {
        val other = Files.createTempDirectory("instance-lock-test-other").toFile()
        try {
            assertTrue(InstanceLock().claim(dataDir))
            // Debug and prod have separate data dirs and running both at once is supported: the
            // claim is per profile, not per machine.
            assertTrue(InstanceLock().claim(other), "a second profile must not be blocked by the first")
        } finally {
            other.deleteRecursively()
        }
    }

    @Test
    fun `claiming twice through the same lock is idempotent`() {
        val lock = InstanceLock()

        assertTrue(lock.claim(dataDir))
        assertTrue(lock.claim(dataDir), "re-claiming through the holder must not refuse its own lock")
    }

    @Test
    fun `a data directory that does not exist yet is created and claimed`() {
        val fresh = File(dataDir, "not/created/yet")

        assertTrue(InstanceLock().claim(fresh))
        assertTrue(fresh.isDirectory)
    }
}
