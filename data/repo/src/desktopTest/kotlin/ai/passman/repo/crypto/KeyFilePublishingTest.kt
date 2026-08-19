package ai.passman.repo.crypto

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The two O_EXCL primitives the PQ key managers publish through.
 *
 * Both exist because a check-then-write can be split by another process — the desktop app has no
 * single-instance lock — and both failure modes destroy exactly the material they handle:
 *
 * - Two quarantines of one key file within a single millisecond used to produce the same
 *   `.corrupt-<timestamp>` name, and `DurableFiles.replace` uses `REPLACE_EXISTING`, so the second
 *   move silently destroyed the first preserved copy — in the one code path whose entire purpose is
 *   preserving it. The claim hands each caller a name the kernel guaranteed was fresh.
 * - Two processes generating a first keypair could both pass `file.exists()` and both publish; the
 *   loser's rename won, orphaning the public key the winner had already handed out. `CREATE_NEW`
 *   lets the kernel pick exactly one winner.
 */
class KeyFilePublishingTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("key-file-publishing").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    // ------------------------------------------------------------ quarantine claims

    @Test
    fun `two claims within one timestamp yield two distinct existing files`() {
        val first = KeyFilePublishing.claimQuarantineDestination(dir, "mldsa.key", timestamp = 777L)
        val second = KeyFilePublishing.claimQuarantineDestination(dir, "mldsa.key", timestamp = 777L)

        assertNotEquals(first.absolutePath, second.absolutePath, "a shared name is a destroyed quarantine copy")
        assertTrue(first.isFile, "a claim must really exist, or a racer can still take the name")
        assertTrue(second.isFile)
    }

    @Test
    fun `claimed names carry the timestamp and then a counter`() {
        val first = KeyFilePublishing.claimQuarantineDestination(dir, "hybrid.key", timestamp = 41L)
        val second = KeyFilePublishing.claimQuarantineDestination(dir, "hybrid.key", timestamp = 41L)
        val third = KeyFilePublishing.claimQuarantineDestination(dir, "hybrid.key", timestamp = 41L)

        assertEquals("hybrid.key.corrupt-41", first.name)
        assertEquals("hybrid.key.corrupt-41-1", second.name)
        assertEquals("hybrid.key.corrupt-41-2", third.name)
    }

    // ------------------------------------------------------------ first-publication claims

    @Test
    fun `publishNew writes the bytes when the name is free`() {
        val target = File(dir, "hybrid.key")

        assertTrue(KeyFilePublishing.publishNew(target, byteArrayOf(1, 2, 3, 4)))
        assertContentEquals(byteArrayOf(1, 2, 3, 4), target.readBytes())
    }

    @Test
    fun `publishNew refuses an existing file and preserves its bytes`() {
        val target = File(dir, "hybrid.key").apply { writeBytes(byteArrayOf(9, 9, 9)) }

        assertFalse(
            KeyFilePublishing.publishNew(target, byteArrayOf(1, 1, 1)),
            "an existing file is another process's published identity - losing the claim, not overwriting it",
        )
        assertContentEquals(byteArrayOf(9, 9, 9), target.readBytes())
    }

    /**
     * A zero-length file is an *existing* file — a crashed claimer's husk. Reclaiming it would need
     * a check-then-write that two racers could both pass, which is the exact hole `CREATE_NEW`
     * closes; the key managers' zero-length quarantine path recovers the husk on the next load.
     */
    @Test
    fun `publishNew refuses even a zero-length file`() {
        val target = File(dir, "mldsa.key").apply { createNewFile() }

        assertFalse(KeyFilePublishing.publishNew(target, byteArrayOf(5)))
        assertEquals(0L, target.length())
    }

    /**
     * The target must never be visible in a half-published state.
     *
     * `CREATE_NEW` claims the name and *then* writes, so the target existed at zero length for the
     * whole write. The key managers read a zero-length key file as a crashed claimer's husk and
     * quarantine it — so a second process starting up during that window moved a live publisher's
     * file aside, generated a second identity, and published that instead. The first process
     * finished writing into an unlinked descriptor and handed its caller a keypair that was not on
     * disk, orphaning every peer it then paired with. That is the one thing `HybridKeyManager`
     * documents as never allowed to happen.
     *
     * A watcher thread samples the target for the duration of a publish. Every sample that sees the
     * file must see it complete.
     */
    @Test
    fun `publishNew never exposes the target in a half-written state`() {
        val target = File(dir, "hybrid.key")
        // Large enough that the write plus fsync is wide enough for a spinning watcher to sample.
        val payload = ByteArray(4 * 1024 * 1024) { (it and 0xFF).toByte() }
        val sightings = java.util.concurrent.ConcurrentLinkedQueue<Long>()
        val publishing = java.util.concurrent.atomic.AtomicBoolean(true)
        val watcher = Thread {
            while (publishing.get()) {
                if (target.exists()) sightings.add(target.length())
            }
        }

        watcher.start()
        try {
            assertTrue(KeyFilePublishing.publishNew(target, payload))
        } finally {
            publishing.set(false)
            watcher.join()
        }

        assertEquals(
            emptyList(),
            sightings.filter { it != payload.size.toLong() }.distinct(),
            "the target was visible at these lengths mid-publish; a concurrent reader would " +
                "quarantine it as a husk and replace this device's identity",
        )
    }
}
