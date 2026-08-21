package ai.passman.crypto.io

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
 * The bounded wait for one artifact directory: [ARTIFACT_DIRECTORY_LOCK_ATTEMPTS] tries of
 * `tryLock`, [ARTIFACT_DIRECTORY_LOCK_RETRY_DELAY_MS] apart — about ten seconds in total.
 *
 * Five times `IdentityStoreLock`'s budget, and for a different reason than that one is two seconds.
 * The longest legitimate holder here is a whole `unbundle`: up to 1,024 entries and 50 MB
 * uncompressed extracted to a staging directory and then renamed into place one file at a time, on
 * whatever storage a phone has. That is seconds, not milliseconds, and timing out on a holder that
 * is genuinely working is worse than waiting for it — the caller's alternative is to fail a key
 * write or reject a peer's push, both of which are real losses to the user.
 *
 * Never the blocking `lock()`, for the reason `IdentityStoreLock` gives: it is uninterruptible and
 * unbounded, so a holder that never releases — a second desktop instance parked at a breakpoint, a
 * stale lock on a network mount — would wedge every key edit and every sync on this account
 * permanently. Exhausting the bound throws [ArtifactDirectoryBusyException] **before** the caller's
 * block runs, so nothing on disk has been touched and retrying later is the whole remedy.
 */
const val ARTIFACT_DIRECTORY_LOCK_ATTEMPTS = 200
const val ARTIFACT_DIRECTORY_LOCK_RETRY_DELAY_MS = 50L
const val ARTIFACT_DIRECTORY_LOCK_BUDGET_MS =
    ARTIFACT_DIRECTORY_LOCK_ATTEMPTS * ARTIFACT_DIRECTORY_LOCK_RETRY_DELAY_MS

/**
 * The bound was reached: somebody else is writing this artifact directory and has not finished.
 *
 * Distinct from every other failure on these paths because the correct response is distinct —
 * nothing on disk was touched, nothing is damaged, and trying again later is the whole remedy.
 */
class ArtifactDirectoryBusyException(message: String) : IllegalStateException(message)

/**
 * Mutual exclusion over one artifact directory — `pgp/<user>/` or `keystore/<user>/` — held by
 * **every** writer into it, sync and foreground alike.
 *
 * ## The race it closes
 *
 * `DirectoryBundler.unbundle` preserves the file it is about to replace by renaming it into a
 * sibling conflict store, then renames the inbound version into place. Those are two steps, and
 * until this lock existed a foreground writer could publish a new version of the same artifact
 * between them. That version was then overwritten having never been preserved — the one remaining
 * way sync could lose key material, and the reason the recovery screen could not honestly say the
 * displaced version had been kept.
 *
 * Foreground writers are not a hypothetical here. Push-receive is a background server running
 * whenever the app is up, while key edits are foreground UI: `PgpClient.changePassword`,
 * `addSubKey`, `removeSubkey` and `updateKeyRingsWithNewKey` all rewrite the live ring path, and
 * they do it with a truncating `FileOutputStream` rather than a temp file and a rename — so the
 * window is not merely "an edit is lost" but "the preserve captures a half-written ring."
 *
 * ## Why it is layered, and why the lock file is a sibling
 *
 * A `ReentrantLock` alone orders threads inside one JVM. The desktop app ships without a
 * single-instance lock, so two logins are one double-click apart — the same reason `IdentityStoreLock`,
 * `KeyringStore.createNew` and `KeyFilePublishing` each exist — and only an OS-level lock spans
 * that. `FileLock` is the one the JVM offers, and it is not sufficient on its own either: two
 * threads of *one* JVM locking the same file get [OverlappingFileLockException] rather than a wait.
 * So the monitor sits above the file lock and keeps this JVM to one contender, exactly as
 * `IdentityStoreLock` and `JvmPasswordDatabaseStorage` do.
 *
 * The lock file is `<artifactDirectory>.lock` — a **sibling** of the directory, never a child, which
 * is what makes it free of every objection `KeyFilePublishing` raises against lock files in these
 * directories. `DirectoryBundler.bundle` walks every descendant of the artifact directory, so a
 * child would ship to a peer and would need a `syncExclusions` entry to stop it; a sibling is
 * outside that walk by construction and needs no filter anywhere. It is equally outside
 * `unbundle`'s canonical-path confinement, so no crafted zip entry reaches it, and outside
 * `DirectoryBundler.preservedCopies`, which reads only the conflict store — so it never appears in
 * the recovery UI as a mysterious empty row.
 *
 * `absoluteFile` before taking the parent is load bearing for the same reason it is in
 * `DirectoryBundler.sibling`: a single-segment relative path has a null parent, and falling back to
 * the directory itself would place the lock file *inside* the tree it must stay out of.
 *
 * ## Lock ordering
 *
 * **This lock is always the OUTER one.** Code that needs both this and `IdentityStoreLock` takes
 * this first; nothing may acquire this while holding `IdentityStoreLock`.
 *
 * The two are not disjoint, though an earlier draft of the design assumed they were. The exclusion
 * list that argument rested on compares basename *strings* while the filesystem resolves *paths*,
 * and `IdentityStoreDisplaceableTest` demonstrates three ways the two disagree on the identity
 * store's own name. So `<user>.pfx` is reachable both by writers holding only this lock and by
 * `JvmKeyStoreClient`'s two `IdentityStoreLock` paths, and the order matters.
 *
 * It is this one outermost because `IdentityStoreLock` is bounded, *fails* rather than waiting, and
 * holds a cross-process `FileLock` of its own. Nested the other way, a writer would block for this
 * lock's whole budget while holding that cross-process lock — the precise wedge `IdentityStoreLock`
 * documents as unacceptable. Outermost, a thread waiting here holds nothing, and an inner
 * busy-timeout unwinds cleanly out of both.
 */
object ArtifactDirectoryLock {

    /** Suffix for the lock file, appended to the artifact directory's own name. */
    private const val LOCK_FILE_SUFFIX = ".lock"

    /**
     * One [State] per artifact directory, keyed by canonical path so that two `File` objects
     * spelling one directory differently meet on the same monitor instead of colliding on the file
     * lock. Never evicted: a process sees a handful of accounts.
     */
    private val states = ConcurrentHashMap<String, State>()

    /**
     * Run [block] holding the lock for [artifactDirectory].
     *
     * Reentrant: a caller already holding this directory's lock — `restorePreserved` calling into
     * the preserve, for instance — re-enters without asking the file lock again.
     *
     * @throws ArtifactDirectoryBusyException if the lock is still held after
     *   [ARTIFACT_DIRECTORY_LOCK_BUDGET_MS]. Thrown before [block] runs, so nothing was touched.
     */
    fun <T> withLock(artifactDirectory: File, block: () -> T): T {
        val lockFile = lockFileFor(artifactDirectory)
        val state = states.computeIfAbsent(canonicalKey(artifactDirectory)) { State() }
        // Bounded here too. The in-JVM holder is running a critical section that is itself bounded,
        // so this cannot legitimately be exceeded; making it a timed wait means no path through this
        // object can hang a key write even if that assumption stops holding.
        if (!state.monitor.tryLock(ARTIFACT_DIRECTORY_LOCK_BUDGET_MS, TimeUnit.MILLISECONDS)) {
            throw ArtifactDirectoryBusyException(
                "artifact directory: ${artifactDirectory.name} was still held by this process after " +
                    "~$ARTIFACT_DIRECTORY_LOCK_BUDGET_MS ms; another sync or key write is in progress",
            )
        }
        try {
            // Only the outermost holder touches the file lock: overlapping locks on one file from
            // one JVM are an error rather than a wait, so a nested acquisition must not ask.
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

    /**
     * `<artifactDirectory>.lock`, resolved as a true sibling.
     *
     * Derived from the **canonical** form, matching [canonicalKey], and that pairing is the point.
     * The monitor is keyed canonically so two spellings of one directory share it; if the lock file
     * were derived from the merely-absolute path they could share a monitor and still lock two
     * different files.
     *
     * A symlinked *prefix* is harmless — paths through it resolve to the same inodes, so
     * `link/alice.lock` and `real/alice.lock` are one file. The case that diverges is the directory's
     * own final component being a link: `aliaslink` -> `alice` gives `aliaslink.lock` from the
     * absolute path and `alice.lock` from the canonical one. In-JVM exclusion hides the difference,
     * because only the outermost holder ever asks the file lock, so a second *process* using the
     * other spelling would lock the other file and proceed. Nothing in this app spells these paths
     * two ways today; the two derivations agreeing is what keeps that from mattering if one ever
     * does.
     *
     * Falls back to the absolute path when canonicalisation fails, for the same reason
     * [canonicalKey] does: a relative path would put the lock file wherever the process happened to
     * be started from.
     *
     * @throws IllegalArgumentException if the directory has no parent — which would mean an artifact
     *   directory at a filesystem root, and there is nowhere safe to put the lock file. Failing is
     *   correct: the alternative fallbacks all put it inside the bundled tree.
     */
    private fun lockFileFor(artifactDirectory: File): File {
        val resolved = runCatching { artifactDirectory.canonicalFile }
            .getOrElse { artifactDirectory.absoluteFile }
        val parent = requireNotNull(resolved.parentFile) {
            "artifact directory has no parent, so its lock file has nowhere to live: $artifactDirectory"
        }
        return File(parent, "${resolved.name}$LOCK_FILE_SUFFIX")
    }

    private fun acquire(state: State, lockFile: File) {
        // The lock file's own directory, not the artifact directory: the artifact directory may not
        // exist yet (a first sync into a fresh account creates it inside the lock), but its parent
        // has to, because that is where the lock file goes.
        lockFile.parentFile?.mkdirs()
        val channel = try {
            FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (failure: IOException) {
            // The directory is read-only, or gone. Not a reason to refuse the write the caller is
            // about to attempt — that write will produce its own, better error if the directory
            // really is unusable — so carry on with the in-process monitor alone.
            KLogger.w(failure) {
                "artifact directory: could not open ${lockFile.absolutePath}; " +
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
                // The filesystem does not implement advisory locking — some network mounts.
                // Degrading is the only option that keeps the account usable, and in-process
                // exclusion still covers Android and a single desktop instance, which is every
                // configuration except two desktop instances on a mount that refuses locks.
                KLogger.w(failure) {
                    "artifact directory: ${lockFile.name} cannot be locked on this filesystem; " +
                        "continuing with in-process exclusion only"
                }
                return
            }
            if (lock != null) {
                state.fileLock = lock
                return
            }
            if (++attempt >= ARTIFACT_DIRECTORY_LOCK_ATTEMPTS) break
            if (attempt == 1) {
                KLogger.i {
                    "artifact directory: ${lockFile.name} is held; waiting up to " +
                        "~$ARTIFACT_DIRECTORY_LOCK_BUDGET_MS ms"
                }
            }
            Thread.sleep(ARTIFACT_DIRECTORY_LOCK_RETRY_DELAY_MS)
        }
        release(state)
        throw ArtifactDirectoryBusyException(
            "artifact directory: ${lockFile.name} was still held after " +
                "~$ARTIFACT_DIRECTORY_LOCK_BUDGET_MS ms; another sync or key write is in progress",
        )
    }

    /**
     * The lock file is closed, never deleted.
     *
     * Unlinking a lock file another process holds open leaves the two of them locking different
     * inodes, which is no lock at all — the same reason `IdentityStoreLock` keeps its own. An empty
     * file beside the artifact directory is cheap, and being a sibling it is invisible to every
     * bundle, every listing and the recovery screen.
     */
    private fun release(state: State) {
        runCatching { state.fileLock?.release() }
        runCatching { state.channel?.close() }
        state.fileLock = null
        state.channel = null
    }

    /**
     * Canonicalised where possible so two spellings of one directory share a monitor.
     *
     * Falls back to the absolute path rather than the raw one: a relative path would key different
     * working directories to the same entry, which is the opposite of the mistake canonicalisation
     * is here to prevent.
     */
    private fun canonicalKey(directory: File): String =
        runCatching { directory.canonicalPath }.getOrElse { directory.absolutePath }

    /** One artifact directory's lock bookkeeping. Only ever touched with [monitor] held. */
    private class State {
        val monitor = ReentrantLock()
        var depth = 0
        var channel: FileChannel? = null
        var fileLock: FileLock? = null
    }
}
