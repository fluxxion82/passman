package ai.passman.repo.crypto

import ai.passman.crypto.io.DurableFiles
import ai.passman.repo.io.SecureFiles
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.StandardOpenOption

/**
 * `O_EXCL` publication for the PQ key managers, chosen over a shared advisory lock deliberately.
 *
 * The races here are cross-*process* — the desktop app ships with no single-instance lock — and a
 * lock file is the wrong tool for this directory twice over: `keystore/<user>/` is a keystore-sync
 * bundle source, so a lock artifact there needs a `DirectoryBundler` exclusion or it ships to a
 * peer; and advisory `FileLock` is exactly what the network mounts this codebase already anticipates
 * are allowed to refuse. `CREATE_NEW` needs no extra artifact, cannot be refused piecemeal, and is
 * the same mechanism `KeyringStore.createNew` already uses for the same failure shape — the kernel
 * picks exactly one winner, and the loser is told rather than silently overwriting.
 */
internal object KeyFilePublishing {

    /**
     * Publish [bytes] at [file] if and only if no file exists there — the first-generation path.
     *
     * A `false` return means another process claimed the name first: its published identity may
     * already be in a peer's hands, so the caller must discard the key it was about to install and
     * fail the load; the next load reads the winner's file. Never retry with an overwriting write.
     *
     * A zero-length file in the way — a crashed claimer's husk — also loses the claim: reclaiming it
     * needs a check-then-write two racers could both pass. The managers' zero-length quarantine path
     * disposes of the husk on the next load instead.
     *
     * Written directly under `CREATE_NEW` rather than temp-file + rename, because a rename replaces
     * unconditionally — it cannot lose to a racer, which is the entire point here. The trade is that
     * a crash mid-write leaves a partial file instead of nothing; for a *first* generation that is
     * recoverable by construction (the identity was never completed, so no peer can hold it), and
     * the quarantine path turns the partial file into a fresh generation on the next load.
     */
    fun publishNew(file: File, bytes: ByteArray): Boolean {
        val channel = try {
            FileChannel.open(file.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        } catch (_: FileAlreadyExistsException) {
            return false
        }
        var complete = false
        try {
            SecureFiles.ownerOnly(file) // owner-only before any key-bearing byte is written
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer) // write() is allowed to be short
            channel.force(true) // content on stable storage before the claim is reported won
            complete = true
        } finally {
            channel.close()
            // A failed publication must not leave the husk this method itself refuses to reclaim.
            if (!complete) file.delete()
            DurableFiles.syncDirectory(file.parentFile)
        }
        return true
    }

    /**
     * Claim a fresh quarantine destination for [baseName] in [directory].
     *
     * The name used to be `<base>.corrupt-<currentTimeMillis>` built with no claim at all, and the
     * move onto it uses `REPLACE_EXISTING` — so two quarantines of the same key file within one
     * millisecond silently destroyed the first preserved copy, in the one code path whose entire
     * purpose is not destroying key material. `Files.createFile` is `O_EXCL`: the returned file is
     * guaranteed fresh, and a collision walks to `-1`, `-2`, … until the kernel grants a name. The
     * caller then moves the unreadable key file *onto its own placeholder*, which `REPLACE_EXISTING`
     * makes atomic and safe.
     *
     * [timestamp] is injectable so a test can force the collision; production uses the clock.
     */
    fun claimQuarantineDestination(
        directory: File,
        baseName: String,
        timestamp: Long = System.currentTimeMillis(),
    ): File {
        var attempt = 0
        while (true) {
            val suffix = if (attempt == 0) "" else "-$attempt"
            val candidate = File(directory, "$baseName.corrupt-$timestamp$suffix")
            try {
                Files.createFile(candidate.toPath())
            } catch (_: FileAlreadyExistsException) {
                attempt++
                continue
            }
            SecureFiles.ownerOnly(candidate)
            return candidate
        }
    }
}
