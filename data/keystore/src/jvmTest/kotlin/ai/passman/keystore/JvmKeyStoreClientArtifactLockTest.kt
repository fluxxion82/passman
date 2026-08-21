package ai.passman.keystore

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.keystore.model.Keystore
import ai.passman.crypto.io.ArtifactDirectoryBusyException
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Every write into `keystore/<user>/` takes the artifact-directory lock.
 *
 * The lock itself is covered by `ArtifactDirectoryLockTest`, and `ArtifactWriterExclusionTest` covers
 * `unbundle`'s half. What is left, and what actually rots, is whether each *call site* still takes
 * it — a future edit that restructures one of these methods can drop the wrap without breaking any
 * behavioural test, because the race it reopens needs a concurrent sync to show.
 *
 * Asserted by holding the lock and watching the call fail to finish. That is a real observation
 * rather than a timing guess: every operation here is milliseconds on a temp directory, so a second
 * without completing means it is waiting for something, and the only thing it can be waiting for is
 * the lock this thread holds.
 */
class JvmKeyStoreClientArtifactLockTest {
    private val client = JvmKeyStoreClient()
    private lateinit var tempDir: File
    private lateinit var keystoreDir: File

    @BeforeTest
    fun setUp() {
        tempDir = Files.createTempDirectory("jvm-keystore-artifact-lock-test").toFile()
        keystoreDir = File(tempDir, "keystore${File.separator}alice").apply { mkdirs() }
    }

    @AfterTest
    fun tearDown() {
        tempDir.deleteRecursively()
    }

    @Test
    fun createKeyStoreTakesTheArtifactLock() = assertHoldsArtifactLockWhileRunning("createKeyStore") {
        client.createKeyStore(
            keystoreType = KeyStoreType.PKCS12,
            keystorePath = keystoreDir.absolutePath,
            keystoreName = "work.pfx",
            keystorePassword = PASSWORD,
            initialKey = null,
        )
    }

    @Test
    fun addKeystoreKeyTakesTheArtifactLock() {
        val keystore = existingKeystore()
        assertHoldsArtifactLockWhileRunning("addKeystoreKey") {
            client.addKeystoreKey(keystore, "added", PASSWORD, KeystoreKeyAlgorithm.AES)
        }
    }

    @Test
    fun deleteKeyStoreKeyTakesTheArtifactLock() {
        val keystore = existingKeystore(initialKey = KeystoreKey("main", PASSWORD, KeystoreKeyAlgorithm.AES))
        assertHoldsArtifactLockWhileRunning("deleteKeyStoreKey") {
            client.deleteKeyStoreKey(keystore, "main")
        }
    }

    @Test
    fun deleteKeystoreTakesTheArtifactLock() {
        val keystore = existingKeystore()
        assertHoldsArtifactLockWhileRunning("deleteKeystore") { client.deleteKeystore(keystore) }
    }

    @Test
    fun changeKeystorePasswordTakesTheArtifactLock() {
        existingKeystore(initialKey = KeystoreKey("main", PASSWORD, KeystoreKeyAlgorithm.AES))
        assertHoldsArtifactLockWhileRunning("changeKeystorePassword") {
            client.changeKeystorePassword(
                keystorePath = keystoreDir.absolutePath,
                keystoreName = "work.pfx",
                keystoreType = KeyStoreType.PKCS12,
                oldPassword = PASSWORD,
                newPassword = "a-new-password",
            )
        }
    }

    /**
     * The identity-store path, which is the one that takes **both** locks.
     *
     * It matters most here. `commitIdentityStore` already held `IdentityStoreLock`; the artifact lock
     * had to go *outside* it, and getting that backwards is the deadlock the whole audit was about.
     * If a future edit moves the artifact lock inside `IdentityStoreLock`, this test still passes —
     * ordering cannot be observed from here — but it does catch the wrap being dropped entirely,
     * which is the likelier regression.
     */
    @Test
    fun createIdentityKeyStoreTakesTheArtifactLock() =
        assertHoldsArtifactLockWhileRunning("createIdentityKeyStore") {
            client.createIdentityKeyStore(
                keystorePath = keystoreDir.absolutePath,
                keystoreName = KeystoreClient.identityStoreName("alice"),
                keystorePassword = IdentityStorePassword.unsafeNotFromKeyring(PASSWORD),
                keyAlias = "identity",
            )
        }

    /**
     * A busy directory is a failed `Result`, not an escaping exception.
     *
     * `addKeystoreKey` reports failure through `Result`, and the lock can refuse when the budget runs
     * out. Taken outside the `runCatching` — which is where the wrap first went — that refusal is
     * thrown at callers who are only prepared for a failed `Result`:
     * `LocalKeystoreRepository.updateKeystore` does not catch, and `AddKeystoreKeyViewModel` calls it
     * from a bare `viewModelScope.launch`. A sync holding the lock past its budget was then a crash
     * on the Add Key button rather than the error the contract promises.
     *
     * This test waits out the real budget, which is the only honest way to reach the path: the
     * production call site takes the default, and a shorter one would be testing a different code
     * path from the one that crashes.
     */
    @Test
    fun addKeystoreKeyReportsABusyDirectoryAsAFailedResult() {
        val keystore = existingKeystore()
        val holderHasIt = CountDownLatch(1)
        val holderMayRelease = CountDownLatch(1)
        val holder = thread {
            ArtifactDirectoryLock.withLock(keystoreDir) {
                holderHasIt.countDown()
                holderMayRelease.await(2, TimeUnit.MINUTES)
            }
        }
        assertTrue(holderHasIt.await(30, TimeUnit.SECONDS), "the holder must get the lock first")

        val result = runCatching {
            client.addKeystoreKey(keystore, "added", PASSWORD, KeystoreKeyAlgorithm.AES)
        }

        holderMayRelease.countDown()
        holder.join(TimeUnit.SECONDS.toMillis(60))

        val returned = assertNotNull(
            result.getOrNull(),
            "addKeystoreKey must return, not throw, when the artifact directory is busy",
        )
        assertTrue(returned.isFailure, "and what it returns must be a failed Result")
        assertIs<ArtifactDirectoryBusyException>(
            returned.exceptionOrNull(),
            "carrying the busy reason, so a caller can tell it from a keystore error",
        )
    }

    private fun existingKeystore(initialKey: KeystoreKey? = null): Keystore =
        client.createKeyStore(
            keystoreType = KeyStoreType.PKCS12,
            keystorePath = keystoreDir.absolutePath,
            keystoreName = "work.pfx",
            keystorePassword = PASSWORD,
            initialKey = initialKey,
        ).getOrThrow()

    /**
     * Assert [call] actually **holds** the artifact-directory lock while it runs.
     *
     * Not "assert it fails to finish within a second". That was the first version of this helper and
     * it was worthless for exactly the calls that matter: a key-password change or an RSA keygen
     * takes longer than a second on its own, so the assertion passed whether or not the lock was
     * ever taken. Mutation caught it — deleting the wrap from `changeKeyPassword` left the test
     * green.
     *
     * This observes the lock itself instead, which is independent of how long the call takes. While
     * the worker runs, the probe repeatedly asks the OS for the same file lock. Within one JVM a
     * request that collides with an existing lock raises [OverlappingFileLockException] rather than
     * waiting, so one such observation is proof the call was holding it at that instant. A call that
     * never takes the lock produces no observation however long it runs.
     */
    private fun assertHoldsArtifactLockWhileRunning(name: String, call: () -> Unit) {
        val lockFile = File(keystoreDir.parentFile, "${keystoreDir.name}.lock")
        var observed = false
        // Retried, because a miss is not a failure. The probe samples while the call runs, so an
        // operation that holds the lock only for microseconds - `deleteKeystore` is a single
        // `File.delete` - can finish between two samples and be missed entirely. That produced a real
        // spurious failure on 2026-08-21 ("the probe never once collided with it") on a call site
        // whose lock was present and correct.
        //
        // Missing N times in a row is what stops being plausible; a call that never takes the lock
        // produces no observation however many times it runs. Every operation probed here is safe to
        // repeat: they either rewrite the same store or delete an already-deleted file, and each
        // takes the lock whether or not there is anything left to do.
        repeat(PROBE_ATTEMPTS) {
            if (observed) return@repeat
            val running = java.util.concurrent.atomic.AtomicBoolean(true)
            val worker = kotlin.concurrent.thread {
                try {
                    runCatching { call() }
                } finally {
                    running.set(false)
                }
            }
            while (running.get() && !observed) {
                observed = artifactLockIsHeld(lockFile)
                Thread.onSpinWait()
            }
            worker.join(java.util.concurrent.TimeUnit.SECONDS.toMillis(120))
        }

        assertTrue(
            observed,
            "$name must hold the artifact-directory lock while it writes; the probe never collided " +
                "with it across $PROBE_ATTEMPTS attempts",
        )
    }

    /** True when some code in this JVM currently holds the OS lock on [lockFile]. */
    private fun artifactLockIsHeld(lockFile: File): Boolean {
        if (!lockFile.isFile) return false
        return try {
            java.nio.channels.FileChannel.open(
                lockFile.toPath(),
                java.nio.file.StandardOpenOption.WRITE,
            ).use { channel ->
                val lock = channel.tryLock()
                if (lock == null) {
                    true // held by another process; cannot happen in a test, but it is still "held"
                } else {
                    lock.release()
                    false
                }
            }
        } catch (_: java.nio.channels.OverlappingFileLockException) {
            true // held elsewhere in this JVM - the worker
        } catch (_: java.io.IOException) {
            false
        }
    }

    private companion object {
        /** Enough that missing a short lock hold every time stops being plausible. */
        const val PROBE_ATTEMPTS = 8

        const val PASSWORD = "artifact-lock-test-password"
    }
}
