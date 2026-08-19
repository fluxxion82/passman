package ai.passman.platform.storage

import ai.passman.crypto.io.DurableFiles
import ai.passman.repo.Platform
import ai.passman.repo.io.SecureFiles
import ai.passman.logging.KLogger
import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock

/**
 * Nothing filters this suffix out of a sync bundle. It is out of a peer's reach only because the
 * `database/` directory is never bundled — `DirectoryBundler.bundle` is called on `pgp/<user>` and
 * `keystore/<user>` and on nothing else. Anything that starts bundling the vault directory has to add
 * an exclusion for this suffix first; there is no guard here to rely on.
 */
private const val PRE_MIGRATION_SUFFIX = ".premigration.v2"

/**
 * The advisory lock every mutating call below takes. One per vault directory rather than one per
 * account: writes are rare, and a single lock keeps the reentrancy bookkeeping to one counter.
 */
private const val LOCK_FILE_NAME = "vault.lock"

/**
 * The bounded wait for the cross-process lock: [VAULT_LOCK_ATTEMPTS] tries of `tryLock`,
 * [VAULT_LOCK_RETRY_DELAY_MS] apart — about a second in total. The only legitimate holder is another
 * instance mid-publish, which is milliseconds of work, so a second of patience covers it with two
 * orders of magnitude to spare; a holder still there after that is not publishing (a debugger, a
 * wedged instance, a stale lock on a network mount) and waiting longer would only turn "no
 * cross-process exclusion this once" into "no vault writes ever again".
 */
internal const val VAULT_LOCK_ATTEMPTS = 20
internal const val VAULT_LOCK_RETRY_DELAY_MS = 50L

class JvmPasswordDatabaseStorage(private val platform: Platform) : PasswordDatabaseStorage {
    private val passwordDbDir = "${platform.getLocalPath()}${File.separator}database${File.separator}"

    private val lockFile = File(passwordDbDir, LOCK_FILE_NAME)

    /**
     * Shared per vault *directory*, not per instance. Lock state that lived in instance fields made
     * two storages over one directory meet on the file lock as overlapping locks from a single JVM —
     * an exception, not a wait — and the second instance degraded to no exclusion at all with only a
     * warning. Two instances is not hypothetical: the desktop app has no single-instance lock, and a
     * second `JvmPasswordDatabaseStorage` is one constructor call away in any future wiring. Keyed on
     * the lock file's absolute path so unrelated directories (tests, multi-account layouts) do not
     * serialise against each other.
     */
    private val lockState = lockStates.computeIfAbsent(lockFile.absolutePath) { VaultLockState() }

    init {
        File(passwordDbDir).apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }
    }

    private fun fileFor(username: String): File =
        File("$passwordDbDir${username.hashCode()}_encrypted_passman.database")

    private fun backupFor(username: String): File =
        File("$passwordDbDir${username.hashCode()}_encrypted_passman.database.bak")

    private fun preMigrationFor(username: String): File =
        File(fileFor(username).path + PRE_MIGRATION_SUFFIX)

    override fun exists(username: String): Boolean = fileFor(username).exists()

    override fun create(username: String, initialEncryptedBytes: ByteArray) {
        // Same durable path as write() so a crash during initial creation cannot
        // leave a half-written file behind.
        write(username, initialEncryptedBytes)
    }

    override fun read(username: String): ByteArray = fileFor(username).readBytes()

    @Synchronized
    override fun delete(username: String) {
        withVaultLock {
            fileFor(username).delete()
        }
    }

    /**
     * Durable, atomic write. Data is written to a UNIQUE temp file, flushed to disk, and then
     * atomically renamed over the target so a reader never observes a partial file and a crash
     * mid-write cannot truncate the existing vault. The previous contents are retained as a single
     * `.bak` generation for manual recovery.
     *
     * [withVaultLock] serialises writers — its shared monitor covers every instance over this
     * directory in this JVM, so concurrent saves (e.g. addPasswordEntry racing the renumber-on-read
     * in getPasswordEntries) cannot collide on the shared temp/backup files, and its advisory file
     * lock extends the same exclusion past the process boundary. `@Synchronized` predates the shared
     * state and is kept as a per-instance belt; the per-write unique temp name is the suspenders.
     */
    @Synchronized
    override fun write(username: String, encryptedBytes: ByteArray) = withVaultLock {
        val target = fileFor(username)

        // Preserve the current good copy before we touch the target. Best-effort: a backup hiccup
        // must never fail the actual save.
        if (target.exists()) {
            runCatching {
                val backup = backupFor(username)
                Files.copy(target.toPath(), backup.toPath(), StandardCopyOption.REPLACE_EXISTING)
                SecureFiles.ownerOnly(backup)
            }
        }

        publish(target, encryptedBytes)
    }

    /**
     * Write-once: an existing downgrade copy is the older, and therefore more useful, one.
     *
     * What the lock covers here is exactly this method: "does a copy exist" and "write one" cannot be
     * split by another writer. It does **not** make retain-then-convert one critical section — the
     * caller's [replaceIfUnchanged] is a separate acquisition, and another writer can land between
     * the two. That interleaving is harmless by *ordering*, not by exclusion: callers retain first
     * and abort the conversion when retention fails, so the one state the compatibility policy
     * forbids — a converted vault with no downgrade copy beside it — is unreachable even though the
     * two steps are two lock regions.
     */
    @Synchronized
    override fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean = withVaultLock {
        require(ciphertext.isNotEmpty()) { "refusing to retain an empty pre-migration copy" }
        val target = preMigrationFor(username)
        if (target.exists() && target.length() > 0L) return@withVaultLock false
        publish(target, ciphertext)
        true
    }

    @Synchronized
    override fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean =
        withVaultLock {
            val target = fileFor(username)
            val current = if (target.isFile) target.readBytes() else ByteArray(0)
            if (!current.contentEquals(expected)) return@withVaultLock false
            write(username, replacement) // reentrant: the monitor and the file lock are already held
            true
        }

    /**
     * Hold the shared in-JVM monitor *and* an advisory lock on `database/vault.lock` for the duration
     * of [block], reentrantly.
     *
     * In-JVM exclusion alone is not enough: the desktop app ships without a single-instance lock —
     * two instances are a double-click away. Across processes the compare in [replaceIfUnchanged] and
     * the publish it gates are separated by a `Files.copy` to `.bak`, a temp write and two fsyncs,
     * which is more than enough room for a second instance to land a save in between and have it
     * silently replaced. `FileLock` is what closes that; the shared [VaultLockState.monitor] is what
     * keeps every thread of *this* JVM — across storage instances, see [lockState] — off the file
     * lock while one of them holds it, since overlapping locks on one file from a single JVM are an
     * error rather than a wait.
     *
     * The file lock is taken with a **bounded** `tryLock` loop, never the blocking `lock()`. The
     * blocking call is uninterruptible and unbounded, so a holder that never releases — a second
     * instance parked at a breakpoint, a stale lock on the network mounts this path already
     * anticipates — would wedge every vault write in this JVM permanently. Exhausting the bound falls
     * through to the same degrade-and-log path a lock-refusing filesystem takes: advisory and
     * best-effort, because a vault that cannot be written is a worse outcome than one written without
     * cross-process exclusion.
     */
    private fun <T> withVaultLock(block: () -> T): T {
        val state = lockState
        state.monitor.lock()
        try {
            if (state.depth++ == 0) acquireVaultLock(state)
            try {
                return block()
            } finally {
                if (--state.depth == 0) releaseVaultLock(state)
            }
        } finally {
            state.monitor.unlock()
        }
    }

    private fun acquireVaultLock(state: VaultLockState) {
        runCatching {
            val channel = FileChannel.open(
                lockFile.toPath(),
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
            )
            state.channel = channel
            SecureFiles.ownerOnly(lockFile)
            var attempt = 0
            var lock: FileLock? = null
            while (true) {
                lock = try {
                    channel.tryLock()
                } catch (_: OverlappingFileLockException) {
                    // Held elsewhere in this JVM, outside this registry (a diagnostic tool, a test
                    // harness). Same meaning as another process holding it: try again.
                    null
                }
                if (lock != null || ++attempt >= VAULT_LOCK_ATTEMPTS) break
                Thread.sleep(VAULT_LOCK_RETRY_DELAY_MS)
            }
            state.fileLock = lock
            if (lock == null) {
                state.channel = null
                channel.close()
                KLogger.w {
                    "vault storage: the cross-process lock was still held after " +
                        "~${VAULT_LOCK_ATTEMPTS * VAULT_LOCK_RETRY_DELAY_MS} ms; " +
                        "continuing with in-process exclusion only"
                }
            }
        }.onFailure {
            KLogger.w(it) {
                "vault storage: could not take the cross-process lock (${it::class.simpleName}); " +
                    "continuing with in-process exclusion only"
            }
            releaseVaultLock(state)
        }
    }

    private fun releaseVaultLock(state: VaultLockState) {
        runCatching { state.fileLock?.release() }
        runCatching { state.channel?.close() }
        state.fileLock = null
        state.channel = null
    }

    /**
     * Publish [bytes] at [target] without ever leaving it absent: unique temp file, fsync, atomic
     * replace, then an fsync of the directory entry itself through [DurableFiles].
     *
     * Not `Files.move(..., ATOMIC_MOVE)` with a blanket `IOException` fallback, which is what this
     * used to be: that fallback also caught genuine write failures and retried them as a plain
     * replace, turning "the disk rejected this" into a second chance to half-apply it. [DurableFiles]
     * narrows the fallback to the one case that means "this filesystem cannot promise atomicity".
     */
    private fun publish(target: File, bytes: ByteArray) {
        val tmp = File.createTempFile("${target.name}.", ".tmp", File(passwordDbDir))
        SecureFiles.ownerOnly(tmp) // owner-only before any plaintext-adjacent bytes are written
        try {
            tmp.outputStream().use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync() // fsync: force bytes to stable storage before the rename
            }
            DurableFiles.replace(tmp, target)
            SecureFiles.ownerOnly(target)
        } finally {
            tmp.delete()
        }
    }

    /** One vault directory's lock bookkeeping. Only ever touched with [monitor] held. */
    private class VaultLockState {
        /** Reentrant and shared across instances: the in-JVM half of the exclusion. */
        val monitor = ReentrantLock()
        var depth = 0
        var channel: FileChannel? = null
        var fileLock: FileLock? = null
    }

    private companion object {
        /** Never evicted: at most a handful of vault directories exist per process. */
        val lockStates = ConcurrentHashMap<String, VaultLockState>()
    }
}
