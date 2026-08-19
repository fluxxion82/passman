package ai.passman.platform.storage

import ai.passman.repo.Platform
import ai.passman.logging.KLogger
import ai.passman.logging.Logger
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Regression tests for the durable-write behavior that stops the vault from being truncated
 * (C6). The old implementation did an in-place `writeBytes`, so a crash mid-write left a
 * truncated file that then tripped the decrypt-failure wipe path.
 */
class JvmPasswordDatabaseStorageTest {
    private lateinit var tmpDir: File
    private lateinit var storage: JvmPasswordDatabaseStorage
    private val user = "alice"

    private fun dbFile(): File = File(tmpDir, "database/${user.hashCode()}_encrypted_passman.database")
    private fun bakFile(): File = File(tmpDir, "database/${user.hashCode()}_encrypted_passman.database.bak")

    @BeforeTest
    fun setUp() {
        tmpDir = Files.createTempDirectory("passman-storage-test").toFile()
        storage = JvmPasswordDatabaseStorage(object : Platform() {
            override fun getLocalPath(): String = tmpDir.absolutePath
        })
    }

    @AfterTest
    fun tearDown() {
        tmpDir.deleteRecursively()
    }

    @Test
    fun writeThenReadRoundTrips() {
        val payload = byteArrayOf(1, 2, 3, 4, 5)
        storage.write(user, payload)
        assertTrue(storage.exists(user))
        assertContentEquals(payload, storage.read(user))
    }

    @Test
    fun createUsesDurablePathAndPersists() {
        val payload = "initial".encodeToByteArray()
        storage.create(user, payload)
        assertTrue(dbFile().exists())
        assertContentEquals(payload, storage.read(user))
    }

    @Test
    fun secondWriteKeepsPreviousContentsAsBackup() {
        val first = "first-generation".encodeToByteArray()
        val second = "second-generation".encodeToByteArray()

        storage.write(user, first)
        assertFalse(bakFile().exists()) // nothing to back up on the first write

        storage.write(user, second)
        assertContentEquals(second, storage.read(user), "target holds the newest write")
        assertTrue(bakFile().exists(), "previous generation is retained")
        assertContentEquals(first, bakFile().readBytes(), "backup holds the prior contents")
    }

    @Test
    fun writeLeavesNoLingeringTempFile() {
        storage.write(user, byteArrayOf(9, 9, 9))
        val stray = File(tmpDir, "database").listFiles()?.filter { it.name.endsWith(".tmp") } ?: emptyList()
        assertEquals(emptyList(), stray, "temp file must be renamed/removed, not left behind")
    }

    /**
     * The conditional replace's compare and write have to be indivisible against a *second instance
     * of the app*, which the desktop build has no lock to prevent — `@Synchronized` stops at the JVM
     * boundary, and between the compare and the publish sit a `Files.copy` to `.bak`, a temp write and
     * two fsyncs. An advisory `FileLock` on `database/vault.lock` is what covers that gap.
     *
     * This asserts the half a single-JVM test can assert: that the lock is *released*. A leaked lock
     * is not a slow app, it is a permanently wedged one — every later write would fail to re-acquire
     * it — and it is invisible to every other test here, all of which would still pass while the
     * storage sat on a lock forever.
     */
    @Test
    fun writeReleasesTheCrossProcessLock() {
        storage.write(user, byteArrayOf(1, 2, 3))

        val lockFile = File(tmpDir, "database/vault.lock")
        assertTrue(lockFile.isFile, "the write must have taken the advisory lock")
        // Overlapping locks on one file from a single JVM are an error rather than a wait, so this
        // succeeds only if the storage gave the lock back.
        FileChannel.open(lockFile.toPath(), StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
            assertNotNull(channel.tryLock(), "the storage is still holding the vault lock after its write")
                .release()
        }
    }

    /**
     * [JvmPasswordDatabaseStorage.replaceIfUnchanged] publishes by calling `write`, so it enters the
     * locked region twice on one thread. The monitor is reentrant for free; the file lock is not,
     * because asking for it again from the same JVM throws rather than waiting.
     *
     * Honest about what this covers: the acquire path degrades to monitor-only exclusion on *any*
     * lock failure, so a broken reentrancy count would be absorbed by that degradation rather than
     * breaking the publish — this asserts the conditional replace still behaves, both when it should
     * publish and when it should not, and does not claim to catch the counter.
     */
    @Test
    fun replaceIfUnchangedPublishesThroughTheReentrantLock() {
        val first = "first".encodeToByteArray()
        storage.write(user, first)

        assertTrue(storage.replaceIfUnchanged(user, first, "second".encodeToByteArray()))
        assertContentEquals("second".encodeToByteArray(), storage.read(user))
        assertFalse(storage.replaceIfUnchanged(user, first, "third".encodeToByteArray()))
        assertContentEquals("second".encodeToByteArray(), storage.read(user))
    }

    /**
     * A held lock means another instance is mid-publish — the correct response is to *wait for it*,
     * not to instantly fall back to no exclusion, which is what an unconditional degrade on
     * `OverlappingFileLockException` amounted to. The foreign holder here is a plain channel in this
     * JVM, which surfaces to the storage exactly like a second process's lock: `tryLock` cannot
     * acquire it.
     */
    @Test
    fun writeWaitsForTheLockHolderInsteadOfInstantlyDegrading() {
        val lockFile = File(tmpDir, "database/vault.lock").apply { createNewFile() }
        FileChannel.open(lockFile.toPath(), StandardOpenOption.WRITE).use { foreign ->
            val held = foreign.lock()
            val done = CountDownLatch(1)
            val writer = Thread {
                storage.write(user, byteArrayOf(7, 7, 7))
                done.countDown()
            }.apply { start() }
            try {
                assertFalse(
                    done.await(300, TimeUnit.MILLISECONDS),
                    "the write must wait for the holder, not degrade the moment the lock is contended",
                )
            } finally {
                held.release()
            }
            assertTrue(done.await(30, TimeUnit.SECONDS), "once the holder releases, the write must proceed")
            writer.join(TimeUnit.SECONDS.toMillis(30))
        }
        assertContentEquals(byteArrayOf(7, 7, 7), storage.read(user))
    }

    /**
     * The other half of the bounded loop: a holder that *never* releases — a debugger, a wedged
     * instance, a stale lock on a network mount — must not hang every vault write forever. The old
     * blocking `channel.lock()` was uninterruptible and unbounded; the loop gives up after its bound
     * and takes the degrade-and-log path that always existed for filesystems that refuse locks.
     */
    @Test
    fun writeStillSucceedsWhenTheLockHolderNeverReleases() {
        val lockFile = File(tmpDir, "database/vault.lock").apply { createNewFile() }
        FileChannel.open(lockFile.toPath(), StandardOpenOption.WRITE).use { foreign ->
            val held = foreign.lock()
            try {
                val started = System.nanoTime()
                storage.write(user, byteArrayOf(4, 4, 4))
                val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                assertTrue(
                    elapsedMs >= (VAULT_LOCK_ATTEMPTS - 1) * VAULT_LOCK_RETRY_DELAY_MS,
                    "the write must exhaust the bounded wait (took ${elapsedMs}ms) before degrading",
                )
            } finally {
                held.release()
            }
        }
        assertContentEquals(byteArrayOf(4, 4, 4), storage.read(user))
    }

    /**
     * Lock state must be shared per vault directory, not per instance. With per-instance state, two
     * storages over one directory met on the file lock as *overlapping* JVM locks, and the second
     * degraded to no exclusion at all with only a warning — on the desktop build, which has no
     * single-instance lock, that is one double-click away. Shared state makes the second instance
     * wait its turn, so a two-instance storm must produce no degrade warning and one intact file.
     */
    @Test
    fun twoInstancesOverOneDirectoryShareTheLockRatherThanDegrading() {
        val capture = CapturingLogger()
        KLogger.registerLoggers(capture)
        try {
            val other = JvmPasswordDatabaseStorage(object : Platform() {
                override fun getLocalPath(): String = tmpDir.absolutePath
            })
            val payloads = (0 until 24).map { "instance-race-$it".encodeToByteArray() }
            val threads = payloads.mapIndexed { index, p ->
                val target = if (index % 2 == 0) storage else other
                Thread { repeat(4) { target.write(user, p) } }
            }
            threads.forEach { it.start() }
            threads.forEach { it.join() }

            assertEquals(
                emptyList(),
                capture.warningsAndErrors().filter { "exclusion" in it },
                "two instances in one JVM must share the lock, not fall back to none",
            )
            val finalBytes = storage.read(user)
            assertTrue(payloads.any { it.contentEquals(finalBytes) }, "final file is one intact payload")
        } finally {
            KLogger.unregisterLoggers(capture)
        }
    }

    /**
     * The structural half of the sharing guarantee, pinned by reflection because it has no behavioural
     * seam: with the bounded retry loop in place, per-instance state only shows as lost exclusion on a
     * filesystem that refuses `FileLock` entirely (some network mounts), which a unit test cannot
     * simulate. On such a mount the shared monitor is the *only* exclusion between two instances, so
     * "both instances resolve the same lock state" is the property that keeps the conditional publish
     * sound there — and unrelated directories must not serialise against each other.
     */
    @Test
    fun lockStateIsSharedPerDirectoryAndDistinctAcrossDirectories() {
        val sameDir = JvmPasswordDatabaseStorage(object : Platform() {
            override fun getLocalPath(): String = tmpDir.absolutePath
        })
        val otherRoot = Files.createTempDirectory("passman-storage-other").toFile()
        try {
            val otherDir = JvmPasswordDatabaseStorage(object : Platform() {
                override fun getLocalPath(): String = otherRoot.absolutePath
            })
            val field = JvmPasswordDatabaseStorage::class.java.getDeclaredField("lockState")
                .apply { isAccessible = true }
            assertTrue(field.get(storage) === field.get(sameDir), "one directory, one lock state")
            assertFalse(field.get(storage) === field.get(otherDir), "different directories must not share")
        } finally {
            otherRoot.deleteRecursively()
        }
    }

    private class CapturingLogger : Logger {
        private val lines = mutableListOf<Pair<Logger.Priority, String?>>()

        override fun log(
            priority: Logger.Priority,
            explicitTag: String?,
            inferredTag: String,
            message: String?,
            throwable: Throwable?,
            properties: Map<String, String>?,
        ) {
            synchronized(lines) { lines += priority to message }
        }

        fun warningsAndErrors(): List<String> = synchronized(lines) {
            lines.filter { it.first == Logger.Priority.WARNING || it.first == Logger.Priority.ERROR }
                .mapNotNull { it.second }
        }
    }

    @Test
    fun concurrentWritesDoNotCrashAndLeaveValidFile() {
        // Reproduces the crash: many overlapping writes (add-entry racing renumber-on-read) must
        // not collide on shared temp/backup files. Each write is a distinct valid payload; after
        // the storm the file must contain exactly one of them intact, with no stray temp files.
        val payloads = (0 until 50).map { "payload-$it".encodeToByteArray() }
        val threads = payloads.map { p ->
            Thread { repeat(4) { storage.write(user, p) } }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        val finalBytes = storage.read(user)
        assertTrue(payloads.any { it.contentEquals(finalBytes) }, "final file is one intact payload")
        val stray = File(tmpDir, "database").listFiles()?.filter { it.name.endsWith(".tmp") } ?: emptyList()
        assertEquals(emptyList(), stray, "no temp files left after concurrent writes")
    }
}
