package ai.passman.platform.transfer

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.keystore.KeystoreClient
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The window this branch exists to close: a foreground key edit landing between the preserve's
 * capture and the commit's install.
 *
 * `unbundle` displaces the live artifact by renaming it into the conflict store and then renames the
 * inbound version into place. Those are two steps. Until every writer took the same lock, a key edit
 * publishing in between was overwritten having never been preserved — the last way sync could lose a
 * version, and the reason the restore dialog could not say the displaced version had been kept.
 */
class ArtifactWriterExclusionTest {
    private lateinit var tempDir: File
    private lateinit var destDir: File
    private lateinit var live: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("artifact-writer-exclusion-test").toFile()
        destDir = File(tempDir, "pgp${File.separator}alice").apply { mkdirs() }
        live = File(destDir, RING)
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    /**
     * A foreground write is never lost to a concurrent unbundle: it ends up live or preserved.
     *
     * Deterministic rather than timing-based, and it asserts a **positive** fact instead of the
     * absence of a race. The test thread holds the artifact lock, starts an unbundle that must
     * therefore wait, and writes the ring while holding it. Whether the unbundle reached the lock
     * before or after that write does not matter — it cannot proceed until the write is done and the
     * lock is released.
     *
     * Two things are asserted, and the first is what makes the second mean anything. The unbundle
     * must **not finish** while the lock is held — that is the property, and an `unbundle` that
     * skipped the lock fails it immediately. The preserve capturing `FOREGROUND` rather than
     * `ORIGINAL` then follows: it can only have run after the write.
     *
     * The outcome assertion alone would not do. If the lock were removed, the unbundle and the write
     * would genuinely race, and a slow unbundle would let the write land first and produce exactly
     * the "correct" result — a test that passes because the defect happened not to fire.
     */
    @Test
    fun aForegroundWriteDuringAnUnbundleIsPreservedNotLost() {
        live.writeBytes(ORIGINAL)
        val unbundleStarted = CountDownLatch(1)
        val unbundleFinished = CountDownLatch(1)

        val syncing = ArtifactDirectoryLock.withLock(destDir) {
            val worker = thread {
                unbundleStarted.countDown()
                DirectoryBundler.unbundle(zipOf(RING to INBOUND), destDir)
                unbundleFinished.countDown()
            }
            assertTrue(unbundleStarted.await(30, TimeUnit.SECONDS), "the unbundle thread must start")
            assertFalse(
                unbundleFinished.await(1, TimeUnit.SECONDS),
                "unbundle must block while the artifact lock is held; this bundle is a few bytes and " +
                    "would otherwise have finished many times over",
            )

            // The foreground edit. In production this is PgpClient rewriting the live ring path with
            // a truncating FileOutputStream, under the same lock this block holds.
            live.writeBytes(FOREGROUND)
            worker
        }
        syncing.join(TimeUnit.SECONDS.toMillis(60))
        assertTrue(unbundleFinished.await(30, TimeUnit.SECONDS), "and must proceed once it is released")

        assertContentEquals(INBOUND, live.readBytes(), "the inbound version should be live afterwards")
        val preserved = DirectoryBundler.preservedCopies(destDir)
        assertEquals(1, preserved.size, "exactly one version was displaced")
        assertContentEquals(
            FOREGROUND,
            preserved.single().readBytes(),
            "the preserve must have captured the foreground write, not the bytes that preceded it",
        )
    }

    /**
     * The truncating-writer case, which is what the PGP writers actually are.
     *
     * `PgpClient` rewrites a secret ring by opening the live path with `FileOutputStream` and
     * encoding into it — no temp file, no rename. Mid-write that path holds a **partial ring**, so
     * an unexcluded preserve would capture a truncated file and call it the saved version. Here the
     * writer holds the lock across the whole open-truncate-write sequence, so the unbundle can only
     * ever see a complete file.
     *
     * Asserted by writing in chunks with the file deliberately left short in between: any capture
     * taken during the write would produce a prefix, and the length assertion catches that.
     */
    @Test
    fun aTruncatingWriteIsNeverObservedHalfDone() {
        live.writeBytes(ORIGINAL)
        val unbundleStarted = CountDownLatch(1)
        val unbundleFinished = CountDownLatch(1)

        val syncing = ArtifactDirectoryLock.withLock(destDir) {
            val worker = thread {
                unbundleStarted.countDown()
                DirectoryBundler.unbundle(zipOf(RING to INBOUND), destDir)
                unbundleFinished.countDown()
            }
            assertTrue(unbundleStarted.await(30, TimeUnit.SECONDS), "the unbundle thread must start")
            assertFalse(
                unbundleFinished.await(1, TimeUnit.SECONDS),
                "unbundle must block while the artifact lock is held",
            )

            live.outputStream().use { out ->
                FOREGROUND.asIterable().chunked(16).forEach { chunk ->
                    out.write(chunk.toByteArray())
                    out.flush()
                }
            }
            worker
        }
        syncing.join(TimeUnit.SECONDS.toMillis(60))

        val preserved = DirectoryBundler.preservedCopies(destDir).single().readBytes()
        assertEquals(
            FOREGROUND.size,
            preserved.size,
            "a preserved copy must be a whole file, never a prefix of one being written",
        )
        assertContentEquals(FOREGROUND, preserved)
    }

    /**
     * `restorePreserved` refuses to put a copy back at an excluded name.
     *
     * An excluded file is never displaced, so a store entry naming one is hand-placed or crash
     * debris. Restoring it writes a file the app treats as device identity, at a path no
     * identity-store lock is held over.
     *
     * The lock file is the sharpest case and the one asserted here: restoring over it would rename
     * the inode `IdentityStoreLock` has open out of the way and install a fresh file at that name,
     * after which one process holds a lock nothing else can see and two commits can publish
     * `<user>.pfx` at once — a lock-integrity failure produced by the recovery UI.
     *
     * Note the store entry is planted with a **well-formed** name — 32 hex characters, the
     * path-complete separator, then the escaped path — so it passes `hasRecoverablePath` and reaches
     * the check under test. A malformed name would be refused for the wrong reason and prove
     * nothing.
     */
    @Test
    fun restorePreservedRefusesToRestoreOverAnExcludedFile() {
        val keystoreDir = File(tempDir, "keystore${File.separator}alice").apply { mkdirs() }
        val exclusions = DirectoryBundler.syncExclusions("alice")
        val store = DirectoryBundler.conflictStore(keystoreDir).apply { mkdirs() }

        listOf(
            KeystoreClient.identityStoreName("alice"),
            KeystoreClient.identityStoreLockName(KeystoreClient.identityStoreName("alice")),
            DirectoryBundler.KEYRING_FILE_NAME,
        ).forEach { excludedName ->
            val planted = File(store, "${"a".repeat(32)}-$excludedName").apply { writeBytes(PLANTED) }
            val target = File(keystoreDir, excludedName).apply { writeBytes(ORIGINAL) }
            assertTrue(
                DirectoryBundler.hasRecoverablePath(planted),
                "precondition: the planted name must parse, or the refusal proves nothing",
            )
            assertEquals(
                excludedName,
                DirectoryBundler.originalPathOf(planted),
                "precondition: and must decode to the excluded path",
            )

            assertFalse(
                DirectoryBundler.restorePreserved(planted, keystoreDir, exclusions),
                "$excludedName is excluded from sync and must not be restorable into the artifact directory",
            )
            assertContentEquals(
                ORIGINAL,
                target.readBytes(),
                "and the live $excludedName must be untouched",
            )
            assertTrue(planted.isFile, "the copy stays in the store, where it can still be exported")
        }
    }

    /**
     * `bundle` takes the lock too, because reading is a critical section here as well.
     *
     * The PGP writers rewrite a live ring with a truncating `FileOutputStream`. A bundle built while
     * one is in flight reads a **prefix** and sends it, and the peer's unbundle installs that
     * truncated ring as its live one — preserving whatever it displaced, which is no comfort, because
     * the damaged file is the one that just arrived. Closing the inbound tear and leaving the
     * outbound one open would have shipped the same corruption the other way.
     */
    @Test
    fun bundleBlocksWhileTheArtifactLockIsHeld() {
        live.writeBytes(ORIGINAL)
        val started = CountDownLatch(1)
        val finished = CountDownLatch(1)

        ArtifactDirectoryLock.withLock(destDir) {
            thread {
                started.countDown()
                DirectoryBundler.bundle(destDir)
                finished.countDown()
            }
            assertTrue(started.await(30, TimeUnit.SECONDS), "the bundling thread must start")
            assertFalse(
                finished.await(1, TimeUnit.SECONDS),
                "bundle must wait for the artifact lock; this directory holds one small file and " +
                    "would otherwise have been zipped many times over",
            )
        }
        assertTrue(finished.await(30, TimeUnit.SECONDS), "and must proceed once it is released")
    }

    /**
     * Restore honours the temp-suffix rule as well as the exclusion set.
     *
     * `unbundle` refuses both — an exact-name set plus everything ending in [DirectoryBundler]'s temp
     * suffix, because a publishing temp carries a random infix no name set can express. A restore
     * that honoured only the first would put such a file back into a live artifact directory, where
     * it is debris its writer's own cleanup no longer knows about.
     */
    @Test
    fun restorePreservedRefusesAPublishingTempName() {
        val store = DirectoryBundler.conflictStore(destDir).apply { mkdirs() }
        val tempName = "keyring.pmk.4821${DirectoryBundler.TEMP_FILE_SUFFIX}"
        val planted = File(store, "${"b".repeat(32)}-$tempName").apply { writeBytes(PLANTED) }
        assertTrue(DirectoryBundler.hasRecoverablePath(planted), "precondition: the name must parse")

        assertFalse(
            DirectoryBundler.restorePreserved(planted, destDir, DirectoryBundler.syncExclusions("alice")),
            "a publishing temp name is refused inbound and must be refused on restore too",
        )
        assertFalse(File(destDir, tempName).exists(), "and nothing may be written at it")
        assertTrue(planted.isFile, "the copy stays in the store")
    }

    /**
     * The control: an ordinary artifact still restores.
     *
     * Without this, a `restorePreserved` that refused everything would satisfy the test above.
     */
    @Test
    fun restorePreservedStillRestoresAnOrdinaryArtifact() {
        live.writeBytes(ORIGINAL)
        DirectoryBundler.unbundle(zipOf(RING to INBOUND), destDir)
        val preserved = DirectoryBundler.preservedCopies(destDir).single()

        assertTrue(
            DirectoryBundler.restorePreserved(preserved, destDir, DirectoryBundler.syncExclusions("alice")),
            "a displaced ring is not an excluded file and must restore",
        )
        assertContentEquals(ORIGINAL, live.readBytes(), "the restored version is live again")
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            entries.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content)
                zip.closeEntry()
            }
        }
        return out.toByteArray()
    }

    private companion object {
        const val RING = "work_secret_ring.asc"
        val ORIGINAL = ByteArray(64) { 0x11 }
        val FOREGROUND = ByteArray(128) { 0x22 }
        val INBOUND = ByteArray(96) { 0x33 }
        val PLANTED = ByteArray(48) { 0x44 }
    }
}
