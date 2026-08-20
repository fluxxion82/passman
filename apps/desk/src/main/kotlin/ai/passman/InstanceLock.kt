package ai.passman

import ai.passman.repo.DesktopProfile
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException

/**
 * Refuses to start a second copy of this app against the same data directory.
 *
 * Two instances do not fail politely. They share one vault file, one `java.util.prefs` node and
 * one credential-store master key, and — the symptom that surfaced this — both try to bind the
 * sync listener on the same port. The loser reports "address already in use" while the peer,
 * pushing at a socket nobody is listening on, reports "Connection reset". Neither message says
 * anything about a second window being open, so the failure reads as a flaky network. That is not
 * hypothetical: it cost a real sync attempt, and the same condition previously presented as a
 * silent 60-second timeout because bind failures used to be swallowed.
 *
 * The claim is per *profile*, not per machine: debug and prod are fully isolated (see
 * [DesktopProfile]) and running one of each at the same time is a normal thing to want. The lock
 * file therefore lives inside the profile's own data directory.
 *
 * ## Why a file lock rather than a pid file or a port
 *
 * A pid file goes stale on a crash and needs liveness probing to tell "still running" from "died
 * holding it". Claiming a port is what the sync listener already does, and doing it twice for two
 * different purposes is how this got confusing in the first place. An OS-level file lock is
 * released by the kernel however the process dies, so a crash can never leave the app unable to
 * start.
 */
class InstanceLock {

    // Both are held for the lifetime of the process and deliberately never closed: releasing
    // either gives up the claim. The field on the file exists because closing the
    // RandomAccessFile would close its channel and drop the lock with it.
    private var lock: FileLock? = null
    private var lockFile: RandomAccessFile? = null

    /**
     * Claims [dataDir], returning false when another process already holds it.
     *
     * The directory is passed in rather than derived so this can run before Koin exists and can be
     * tested against a temp directory. In production it is the profile's data dir — the same one
     * [ai.passman.repo.DesktopPlatform] resolves.
     */
    fun claim(dataDir: File): Boolean {
        if (lock != null) return true

        val file = runCatching {
            dataDir.mkdirs()
            RandomAccessFile(File(dataDir, LOCK_FILE_NAME), "rw")
        }.getOrElse {
            // A directory we cannot even open a file in is not a claim we can adjudicate. Start,
            // rather than making the app unlaunchable over a guard that is meant to prevent a
            // lesser problem than "will not run".
            return true
        }

        return runCatching {
            // tryLock returns null when another *process* holds the lock, and throws
            // OverlappingFileLockException when this JVM already does.
            val acquired = file.channel.tryLock()
            if (acquired == null) {
                file.close()
                false
            } else {
                lockFile = file
                lock = acquired
                true
            }
        }.getOrElse { failure ->
            file.runCatching { close() }
            // Same JVM already holds it — for the caller that is indistinguishable from another
            // process holding it, and the answer is the same.
            if (failure is OverlappingFileLockException) return false
            // A filesystem that cannot lock at all (some network mounts) must not make the app
            // unlaunchable. Accept the risk this guard was meant to remove; refusing to run would
            // be the worse failure.
            true
        }
    }

    private companion object {
        const val LOCK_FILE_NAME = "passman.instance.lock"
    }
}
