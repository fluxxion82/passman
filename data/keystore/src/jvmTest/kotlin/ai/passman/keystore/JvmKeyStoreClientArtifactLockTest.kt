package ai.passman.keystore

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.keystore.model.Keystore
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
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
        val running = java.util.concurrent.atomic.AtomicBoolean(true)
        var observed = false

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

        assertTrue(
            observed,
            "$name must hold the artifact-directory lock while it writes; the probe never once " +
                "collided with it",
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
        const val PASSWORD = "artifact-lock-test-password"
    }
}
