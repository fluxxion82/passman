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
    /** Long enough to be a real wait, short enough that the contended tests stay fast. */
    private val SHORT_BUDGET_MS = 400L


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
     * When the artifact directory's own final component is a symlink, the lock file follows the
     * **canonical** name — so a second spelling cannot lock a second file.
     *
     * A symlinked *parent* is not the interesting case and cannot show this: paths through it
     * resolve to the same inodes, so `link/alice.lock` and `real/alice.lock` are one file either
     * way. It is when the directory itself is the link that the two derivations diverge —
     * `aliaslink` -> `alice` yields `aliaslink.lock` from the absolute path and `alice.lock` from the
     * canonical one, two genuinely different files.
     *
     * That matters because the monitor is keyed canonically, so both spellings share it and in-JVM
     * exclusion looks fine; only the outermost holder ever asks the file lock. A second *process*
     * using the other spelling would lock the other file and walk straight through. Keying the
     * monitor and deriving the lock file the same way is what forecloses it.
     */
    @Test
    fun aSymlinkedDirectoryLocksTheCanonicalFileNotOneBesideTheLink() {
        val canonicalDir = File(tempDir, "alice").apply { mkdirs() }
        val linkDir = File(tempDir, "aliaslink")
        java.nio.file.Files.createSymbolicLink(linkDir.toPath(), canonicalDir.toPath())

        ArtifactDirectoryLock.withLock(linkDir) {
            val canonicalLock = File(tempDir, "alice.lock")
            assertTrue(
                canonicalLock.isFile,
                "the lock file must be named for the canonical directory, not the link",
            )
            assertFalse(
                File(tempDir, "aliaslink.lock").isFile,
                "and no second lock file may appear beside the link",
            )
            FileChannel.open(canonicalLock.toPath(), StandardOpenOption.WRITE).use { channel ->
                assertFailsWith<OverlappingFileLockException>(
                    "the canonical lock file must be the one actually held",
                ) {
                    channel.tryLock()
                }
            }
        }
    }

    /**
     * Timing out **inside `acquire`** throws rather than hangs, and leaves the lock usable.
     *
     * Contended on the file lock from outside the registry, deliberately. An earlier version put the
     * contention on the monitor, where the wait ends before `acquire` is ever called — so it never
     * executed the failure path it claimed to cover, and deleting the `release` from that path left
     * it green.
     *
     * What it can and cannot show: it does now execute the catch block, so an exception or a held
     * monitor there is caught by the reacquire below. Whether the *channel* was closed is not
     * observable through this object — a leaked descriptor changes nothing a caller can see, and it
     * is reclaimed by GC before a descriptor count can measure it. That one line is held by review,
     * not by this test, and saying so is better than a test that cannot fail.
     */
    @Test
    fun timingOutInsideAcquireThrowsAndLeavesTheLockUsable() {
        val lockFile = File(artifactDir.parentFile, "${artifactDir.name}.lock")
        lockFile.createNewFile()

        FileChannel.open(lockFile.toPath(), StandardOpenOption.WRITE).use { channel ->
            val outsider = channel.tryLock()
            assertTrue(outsider != null, "precondition: the file lock must be held from outside the registry")
            try {
                assertFailsWith<ArtifactDirectoryBusyException>("a contended acquire must end in Busy, not a hang") {
                    ArtifactDirectoryLock.withLock(artifactDir, SHORT_BUDGET_MS) { }
                }
            } finally {
                outsider?.release()
            }
        }

        var reacquired = false
        ArtifactDirectoryLock.withLock(artifactDir) { reacquired = true }
        assertTrue(reacquired, "a timed-out acquire must not leave the lock unusable")
    }

    /**
     * The **file-lock** stage honours the caller's budget, not a fixed attempt count.
     *
     * The retry loop counts attempts, and the count was tuned to the default budget, so the wait it
     * produced had nothing to do with the deadline: waiting out the monitor and then waiting the full
     * attempt count made the real worst case roughly double what the constants, the KDoc and both
     * exception messages promise. A bound nobody can state is not a bound.
     *
     * Isolated to the second stage deliberately. The test thread takes the file lock directly,
     * outside the registry, leaving the monitor free — so the single waiter passes stage one instantly
     * and everything measured belongs to stage two. A fixture with two waiters cannot show this:
     * whichever one holds the monitor holds it for the *whole* of its own file-lock wait, so the
     * other times out on the monitor and never reaches the stage under test. That is what the first
     * two versions of this test got wrong, and mutation is what said so both times.
     */
    @Test
    fun theFileLockStageHonoursTheBudgetRatherThanAnAttemptCount() {
        val lockFile = File(artifactDir.parentFile, "${artifactDir.name}.lock")
        lockFile.createNewFile()

        FileChannel.open(lockFile.toPath(), StandardOpenOption.WRITE).use { channel ->
            val outsider = channel.tryLock()
            assertTrue(outsider != null, "precondition: the file lock must be held from outside the registry")
            try {
                val startedAt = System.nanoTime()
                assertFailsWith<ArtifactDirectoryBusyException> {
                    ArtifactDirectoryLock.withLock(artifactDir, SHORT_BUDGET_MS) { }
                }
                val waitedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)

                // Both bounds. The upper one catches a wait governed by the attempt count instead of
                // the deadline. The lower one catches the opposite mutation — a `remainingMillis` that
                // always returns zero makes every contended acquire fail instantly, which is still a
                // Busy and still under any upper bound, so an upper bound alone would call that a pass.
                assertTrue(
                    waitedMs >= SHORT_BUDGET_MS / 2,
                    "a contended acquire must actually wait for its budget; gave up after $waitedMs ms",
                )
                assertTrue(
                    waitedMs < SHORT_BUDGET_MS * 4,
                    "the file-lock wait must end at the caller's budget; waited $waitedMs ms against " +
                        "a budget of $SHORT_BUDGET_MS ms",
                )
            } finally {
                outsider?.release()
            }
        }
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
