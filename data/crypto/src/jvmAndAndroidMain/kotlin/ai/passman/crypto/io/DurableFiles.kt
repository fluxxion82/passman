package ai.passman.crypto.io

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Publishing a freshly written temp file over an irreplaceable target, without ever leaving the
 * target absent.
 *
 * ## Why this is not `File.renameTo`
 *
 * `File.renameTo` is documented to be platform dependent, and on Windows it **fails when the
 * destination already exists**. Every call site that wrote `if (!tmp.renameTo(target)) {
 * target.delete(); tmp.renameTo(target) }` therefore took the delete-then-rename branch as its
 * *normal* path on Windows — which the desktop app ships (`TargetFormat.Msi`). Between the `delete`
 * and the retry the file exists under neither name; a crash there, or a second rename that also
 * fails, destroys the only copy. For a PKCS#12 identity store or a device keyring that is permanent
 * account loss.
 *
 * `Files.move` with `ATOMIC_MOVE` maps to `rename(2)` on POSIX and `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`
 * on Windows. Both replace an existing destination in one step, so there is no instant at which the
 * target is missing.
 *
 * ## Why the directory is fsynced
 *
 * Writers fsync the temp file's *contents* before the move, which is necessary but not sufficient:
 * the rename is a change to the parent **directory**, and on a crash an un-fsynced directory can
 * come back pointing at the old entry (or at nothing) even though the data blocks are safely on
 * disk. Syncing the directory afterwards is what makes the swap itself durable.
 *
 * ## Why it lives in `data:crypto`
 *
 * `data:keystore` and `data:local:platform` both need it and neither depends on the other;
 * `data:crypto` is the deepest module both already depend on. It is file plumbing rather than
 * cryptography, but a second copy of an atomic-move routine is the kind of thing that drifts, and
 * these two copies guard the two files whose loss is unrecoverable.
 */
object DurableFiles {

    /**
     * Move [source] onto [target], replacing it, without ever leaving [target] absent.
     *
     * Falls back to a plain `REPLACE_EXISTING` move when the filesystem cannot promise atomicity
     * (`AtomicMoveNotSupportedException`, typically a cross-device move). That fallback is still a
     * replace: it never unlinks the target as a separate step, so the "no copy anywhere" window the
     * delete-then-rename idiom opened does not come back.
     *
     * @throws IOException if the move fails. The caller still holds [source]; nothing was destroyed.
     */
    fun replace(source: File, target: File) {
        try {
            Files.move(
                source.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        syncDirectory(target.parentFile)
    }

    /**
     * Best-effort fsync of [directory]'s own entries, so a rename or create in it survives a power
     * cut rather than only a process crash.
     *
     * Best-effort because there is no portable way to do it: Windows cannot open a directory as a
     * channel at all, and some filesystems reject the force. A failure here means the *ordering*
     * guarantee is weaker than intended, never that the data is wrong, so it must not fail the
     * write that just succeeded.
     */
    fun syncDirectory(directory: File?) {
        if (directory == null) return
        try {
            FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
        } catch (_: IOException) {
            // Windows: a directory cannot be opened as a channel. Nothing to do.
        } catch (_: UnsupportedOperationException) {
            // A filesystem provider that does not support directory channels.
        }
    }
}
