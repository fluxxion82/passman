package ai.passman.keystore

import ai.passman.logging.KLogger
import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

/**
 * The bounded wait for one identity store's lock: [IDENTITY_STORE_LOCK_ATTEMPTS] tries of `tryLock`,
 * [IDENTITY_STORE_LOCK_RETRY_DELAY_MS] apart — about two seconds in total.
 *
 * Longer than `JvmPasswordDatabaseStorage`'s one-second vault budget on purpose: the critical
 * sections here contain PBE. A commit writes the replacement and *reads it back*, and a recovery
 * opens the backup — which may be a pre-migration store still carrying the JCA writer's 600,000
 * iterations — so a legitimate holder on a slow phone can hold this for the better part of a second.
 * Two orders of magnitude over the fast path and one over the slow one.
 *
 * Never the blocking `lock()`. That call is uninterruptible and unbounded, so a holder that never
 * releases — a second desktop instance parked at a breakpoint, a stale lock on a network mount —
 * would wedge every login on this account permanently. Exhausting the bound is reported instead:
 * a commit fails with a message naming the lock and a recovery declines, both of which leave every
 * file exactly as it was.
 */
internal const val IDENTITY_STORE_LOCK_ATTEMPTS = 40
internal const val IDENTITY_STORE_LOCK_RETRY_DELAY_MS = 50L
internal const val IDENTITY_STORE_LOCK_BUDGET_MS =
    IDENTITY_STORE_LOCK_ATTEMPTS * IDENTITY_STORE_LOCK_RETRY_DELAY_MS

/**
 * The bound was reached: somebody else is publishing this identity store and has not finished.
 *
 * Distinct from every other failure on these paths because the correct response is distinct — nothing
 * on disk was touched, nothing is damaged, and trying again later is the whole remedy.
 */
internal class IdentityStoreBusyException(message: String) : IllegalStateException(message)

/**
 * Mutual exclusion over one account's identity store, held by both writers of it:
 * `JvmKeyStoreClient.commitIdentityStore` and `JvmKeyStoreClient.restoreIdentityKeyStoreFromBackup`.
 *
 * ## The race it closes
 *
 * The two paths write the same three files — `<name>.pfx`, its `.bak`, and a temp — and reach
 * opposite conclusions about them. A recovery decides "the live store is unreadable, the backup is
 * good, publish it"; a commit decides "here is a new store, publish it and the backup is now debris".
 * Interleaved, the recovery's decision goes stale between the reading and the publishing:
 *
 * 1. login B sees a live store mid-`DurableFiles.replace` (the cross-device fallback is a copy, so
 *    there is a window where the file is short) and starts a recovery;
 * 2. login A's commit finishes, verifies its replacement, deletes the backup;
 * 3. login B publishes the copy it took in step 1.
 *
 * The store is now the *pre*-commit one, the backup is gone, and if step 2 was the
 * login-password→derived-password migration then that migration reported success and was then
 * silently reverted. Serialising the two paths is half the fix; the other half is
 * `restoreIdentityKeyStoreFromBackup` re-testing the live store *after* it holds the lock, because
 * this object can only order the two writers, not make B's earlier reading true again.
 *
 * ## Why a lock file, and why it is layered
 *
 * The racers are separate **processes**: the desktop app ships without a single-instance lock, so two
 * logins are one double-click apart. Only an OS-level lock spans that, and `FileLock` is the one the
 * JVM offers. It is not sufficient by itself — two threads of *one* JVM locking the same file get
 * [OverlappingFileLockException] rather than a wait — so a [ReentrantLock] keyed by the lock file's
 * canonical path sits above it and keeps this JVM to one contender, exactly as
 * `JvmPasswordDatabaseStorage` does for the vault. Unrelated accounts key to different paths and do
 * not serialise against each other.
 *
 * `KeyFilePublishing` argues against a lock file for the PQ key managers and picks `O_EXCL` instead;
 * the difference is that those publish under a name nobody else may take, which `CREATE_NEW` decides
 * on its own, whereas these two paths both mean to replace the *same* existing file and have to be
 * ordered rather than arbitrated. The two objections it raises are answered rather than ignored: the
 * lock file's name is deterministic and carried into `DirectoryBundler.syncExclusions` so it cannot
 * ship to a peer, and a filesystem that refuses advisory locking degrades to in-process exclusion
 * with a warning instead of making the account unwritable.
 */
internal object IdentityStoreLock {

    /**
     * One [State] per lock file, keyed by canonical path so that two `JvmKeyStoreClient` instances —
     * or two `File` objects spelling the same directory differently — meet on the same monitor
     * instead of colliding on the file lock. Never evicted: a process sees a handful of accounts.
     */
    private val states = ConcurrentHashMap<String, State>()

    /**
     * Run [block] holding the lock for [keystoreName] in [folder].
     *
     * @throws IdentityStoreBusyException if the lock is still held after
     *   [IDENTITY_STORE_LOCK_BUDGET_MS]. Thrown before [block] runs, so nothing has been touched.
     */
    fun <T> withLock(folder: File, keystoreName: String, block: () -> T): T {
        val lockFile = File(folder, KeystoreClient.identityStoreLockName(keystoreName))
        val state = states.computeIfAbsent(canonicalKey(lockFile)) { State() }
        // Bounded here too. The in-JVM holder is running a critical section that is itself bounded, so
        // this cannot legitimately be exceeded; making it a timed wait means no path through this
        // object can hang a login even if that assumption stops holding.
        if (!state.monitor.tryLock(IDENTITY_STORE_LOCK_BUDGET_MS, TimeUnit.MILLISECONDS)) {
            throw IdentityStoreBusyException(
                "identity store: ${lockFile.name} was still held by this process after " +
                    "~$IDENTITY_STORE_LOCK_BUDGET_MS ms; another commit or recovery is in progress",
            )
        }
        try {
            // Reentrant, and only the outermost holder touches the file lock: overlapping locks on one
            // file from one JVM are an error rather than a wait, so a nested acquisition must not ask.
            if (state.depth == 0) acquire(state, lockFile)
            state.depth++
            try {
                return block()
            } finally {
                if (--state.depth == 0) release(state)
            }
        } finally {
            state.monitor.unlock()
        }
    }

    private fun acquire(state: State, lockFile: File) {
        val channel = try {
            FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (failure: IOException) {
            // The directory is read-only, or gone. Not a reason to refuse the write the caller is
            // about to attempt — that write will produce its own, better error if the directory really
            // is unusable — so carry on with the in-process monitor alone.
            KLogger.w(failure) {
                "identity store: could not open ${lockFile.absolutePath}; " +
                    "continuing with in-process exclusion only"
            }
            return
        }
        state.channel = channel
        var attempt = 0
        while (true) {
            val lock = try {
                channel.tryLock()
            } catch (_: OverlappingFileLockException) {
                // Held elsewhere in this JVM, outside this registry (a test harness, a diagnostic
                // tool). Same meaning as another process holding it: wait and ask again.
                null
            } catch (failure: IOException) {
                // The filesystem does not implement advisory locking — some network mounts. Degrading
                // is the only option that keeps the account usable, and the recovery path's re-check
                // under the lock still narrows the window to the width of a single `isFile` test.
                KLogger.w(failure) {
                    "identity store: ${lockFile.name} cannot be locked on this filesystem; " +
                        "continuing with in-process exclusion only"
                }
                return
            }
            if (lock != null) {
                state.fileLock = lock
                return
            }
            if (++attempt >= IDENTITY_STORE_LOCK_ATTEMPTS) break
            if (attempt == 1) {
                KLogger.i {
                    "identity store: ${lockFile.name} is held; waiting up to ~$IDENTITY_STORE_LOCK_BUDGET_MS ms"
                }
            }
            Thread.sleep(IDENTITY_STORE_LOCK_RETRY_DELAY_MS)
        }
        release(state)
        throw IdentityStoreBusyException(
            "identity store: ${lockFile.name} was still held after ~$IDENTITY_STORE_LOCK_BUDGET_MS ms; " +
                "another commit or recovery is in progress",
        )
    }

    /** The lock file is closed, never deleted — see `KeystoreClient.IDENTITY_STORE_LOCK_SUFFIX`. */
    private fun release(state: State) {
        runCatching { state.fileLock?.release() }
        runCatching { state.channel?.close() }
        state.fileLock = null
        state.channel = null
    }

    private fun canonicalKey(lockFile: File): String =
        runCatching { lockFile.canonicalPath }.getOrDefault(lockFile.absolutePath)

    /** One identity store's lock bookkeeping. Only ever touched with [monitor] held. */
    private class State {
        val monitor = ReentrantLock()
        var depth = 0
        var channel: FileChannel? = null
        var fileLock: FileLock? = null
    }
}
