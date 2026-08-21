package ai.passman.crypto.io

import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ArtifactDirectoryLockTest {
    private lateinit var tempDir: File
    private lateinit var artifactDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("artifact-directory-lock-test").toFile()
        artifactDir = File(tempDir, "pgp${File.separator}alice").apply { mkdirs() }
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    /**
     * The placement the whole design rests on: a **sibling**, never a child.
     *
     * `DirectoryBundler.bundle` walks every descendant of the artifact directory, so a lock file
     * inside it would be pushed to every paired peer and would need a `syncExclusions` entry to stop
     * that. A sibling is outside the walk by construction. It is also outside
     * `DirectoryBundler.preservedCopies`, which reads only the conflict store, so it cannot show up
     * in the recovery screen as an empty row the user cannot explain.
     */
    @Test
    fun theLockFileIsASiblingOfTheArtifactDirectoryNotAChild() {
        ArtifactDirectoryLock.withLock(artifactDir) {
            val lockFile = File(artifactDir.parentFile, "${artifactDir.name}.lock")
            assertTrue(lockFile.isFile, "the lock file must exist at <artifactDir>.lock while held")
            assertEquals(
                artifactDir.parentFile.canonicalPath,
                lockFile.parentFile.canonicalPath,
                "the lock file must live beside the artifact directory",
            )
            assertTrue(
                artifactDir.walkTopDown().none { it.name.endsWith(".lock") },
                "nothing inside the artifact directory may be a lock file - bundle() walks this tree",
            )
        }
    }

    /**
     * The cross-process half is really taken, not just the in-JVM monitor.
     *
     * Asserted by asking for the same file lock through a **second channel**. Within one JVM that is
     * an [OverlappingFileLockException] rather than a wait — which is precisely the evidence wanted
     * here, because it can only be thrown if a `FileLock` on that file is genuinely held. Were the
     * file-lock layer missing or silently degraded, `tryLock` would return a lock instead.
     *
     * This is what makes the guarantee hold across two desktop instances, which ship without any
     * single-instance lock.
     */
    @Test
    fun holdingTheLockReallyHoldsAnOsFileLock() {
        val lockFile = File(artifactDir.parentFile, "${artifactDir.name}.lock")

        ArtifactDirectoryLock.withLock(artifactDir) {
            FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
                .use { channel ->
                    assertFailsWith<OverlappingFileLockException>(
                        "a second lock request on the lock file must collide with the one being held",
                    ) {
                        channel.tryLock()
                    }
                }
        }

        // And it is released afterwards, so the next holder is not locked out by a leak.
        FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
            .use { channel ->
                val lock = channel.tryLock()
                assertTrue(lock != null, "the file lock must be released when the block returns")
                lock?.release()
            }
    }

    /**
     * The lock file survives release rather than being deleted.
     *
     * Unlinking a lock file another process holds open leaves the two of them locking different
     * inodes, which is no exclusion at all — the same reason `IdentityStoreLock` keeps its own. An
     * empty sibling file is the cost.
     */
    @Test
    fun theLockFileIsKeptAfterRelease() {
        ArtifactDirectoryLock.withLock(artifactDir) { }

        assertTrue(
            File(artifactDir.parentFile, "${artifactDir.name}.lock").isFile,
            "the lock file must not be deleted on release",
        )
    }

    /**
     * Reentrant, because the production code nests: `restorePreserved` takes the lock and then calls
     * the preserve, which is also reachable directly from `unbundle`.
     *
     * The nested acquisition must not ask for the file lock again — overlapping locks on one file
     * from one JVM are an error, not a wait, so a naive re-acquire would turn every restore into an
     * exception. Asserted by nesting three deep and then confirming the file lock is still held once
     * the inner frames have returned.
     */
    @Test
    fun theLockIsReentrantAndOnlyTheOutermostFrameTouchesTheFileLock() {
        val lockFile = File(artifactDir.parentFile, "${artifactDir.name}.lock")
        var reached = 0

        ArtifactDirectoryLock.withLock(artifactDir) {
            ArtifactDirectoryLock.withLock(artifactDir) {
                ArtifactDirectoryLock.withLock(artifactDir) { reached++ }
            }
            // The inner frames have returned; the outermost one still holds the file lock.
            FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
                .use { channel ->
                    assertFailsWith<OverlappingFileLockException>(
                        "an inner frame returning must not have released the outer frame's file lock",
                    ) {
                        channel.tryLock()
                    }
                }
        }

        assertEquals(1, reached, "the innermost block must actually run")
        FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
            .use { channel ->
                val lock = channel.tryLock()
                assertTrue(lock != null, "and the outermost frame must release it on the way out")
                lock?.release()
            }
    }

    /**
     * Threads are genuinely serialised — the property every wrapped call site is buying.
     *
     * Each worker flips a shared flag on entry and clears it on exit. If two ever overlap, one of
     * them sees the flag already set and records a violation, so a broken lock is caught by a
     * positive observation rather than by a timing guess.
     *
     * This asserts the **combined** guarantee and deliberately does not try to attribute it to one
     * layer. Mutating the monitor away leaves this passing, because within one JVM a second
     * `tryLock` on the lock file raises `OverlappingFileLockException`, which [ArtifactDirectoryLock]
     * treats as "held, wait and retry" — so the file lock alone still serialises, just slowly and via
     * an exception path. The monitor's own contribution is pinned by
     * [theLockIsReentrantAcrossDifferentSpellingsOfOneDirectory] instead, which cannot pass without
     * it.
     */
    @Test
    fun concurrentHoldersAreSerialised() {
        val inside = AtomicBoolean(false)
        val overlaps = AtomicInteger(0)
        val completed = AtomicInteger(0)
        val start = CountDownLatch(1)

        val workers = (1..8).map {
            thread {
                start.await()
                repeat(50) {
                    ArtifactDirectoryLock.withLock(artifactDir) {
                        if (!inside.compareAndSet(false, true)) overlaps.incrementAndGet()
                        // Long enough that an unlocked run really does overlap, short enough to stay fast.
                        Thread.yield()
                        inside.set(false)
                        completed.incrementAndGet()
                    }
                }
            }
        }
        start.countDown()
        workers.forEach { it.join(TimeUnit.SECONDS.toMillis(60)) }

        assertEquals(400, completed.get(), "every worker iteration must have run")
        assertEquals(0, overlaps.get(), "no two holders may be inside the lock at once")
    }

    /**
     * Two different artifact directories do not serialise against each other.
     *
     * `pgp/<user>/` and `keystore/<user>/` are synced independently and edited independently, and so
     * are two accounts' directories. A single global lock would make an inbound PGP push wait behind
     * an unrelated keystore write, which is exactly the kind of coupling that turns a correctness fix
     * into a performance complaint.
     *
     * Asserted by holding one and taking the other from another thread: if they shared a lock, the
     * second thread could not finish while the first is still inside.
     */
    @Test
    fun unrelatedArtifactDirectoriesDoNotContend() {
        val other = File(tempDir, "keystore${File.separator}alice").apply { mkdirs() }
        val otherFinished = CountDownLatch(1)

        ArtifactDirectoryLock.withLock(artifactDir) {
            thread { ArtifactDirectoryLock.withLock(other) { otherFinished.countDown() } }
            assertTrue(
                otherFinished.await(30, TimeUnit.SECONDS),
                "a different artifact directory must not wait on this one",
            )
        }
    }

    /**
     * Two spellings of one directory meet on the same monitor — asserted by **reentrancy**, which is
     * the only observation that can tell the shared registry apart from the file lock.
     *
     * The keys come from callers that build paths by string concatenation — `"$keystoreDir$user"`,
     * `File(destDir, relative)` — so one directory genuinely does arrive spelled differently, and
     * `restorePreserved` nests a second acquisition inside the first.
     *
     * Mutual exclusion cannot distinguish the two layers: with the registry broken, a second
     * spelling still collides on the lock file and still waits. Reentrancy can. A same-thread nested
     * call that failed to find its own [State] would ask the file lock for a second time, collide
     * with the lock this very thread is holding, exhaust the retry budget and throw
     * [ArtifactDirectoryBusyException] — a self-deadlock reported as contention. Re-entering
     * promptly is proof the two spellings resolved to one entry.
     */
    @Test
    fun theLockIsReentrantAcrossDifferentSpellingsOfOneDirectory() {
        val spelledAwkwardly = File(tempDir, "pgp${File.separator}.${File.separator}alice")
        var reached = false

        ArtifactDirectoryLock.withLock(artifactDir) {
            ArtifactDirectoryLock.withLock(spelledAwkwardly) { reached = true }
        }

        assertTrue(reached, "a nested call naming the same directory differently must re-enter")
    }

    /**
     * And two spellings really are mutually exclusive across threads.
     *
     * Weaker than the test above — the file lock alone would satisfy it — but it states the
     * user-visible property directly, so it stays.
     */
    @Test
    fun differentSpellingsOfOneDirectoryExcludeEachOther() {
        val spelledAwkwardly = File(tempDir, "pgp${File.separator}.${File.separator}alice")
        val otherFinished = CountDownLatch(1)

        ArtifactDirectoryLock.withLock(artifactDir) {
            thread { ArtifactDirectoryLock.withLock(spelledAwkwardly) { otherFinished.countDown() } }
            assertFalse(
                otherFinished.await(1, TimeUnit.SECONDS),
                "the same directory spelled differently must contend for the same lock",
            )
        }
        assertTrue(
            otherFinished.await(30, TimeUnit.SECONDS),
            "and must proceed once the first holder releases",
        )
    }
}
