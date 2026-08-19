package ai.passman.platform.keyring

import ai.passman.crypto.io.DurableFiles
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.io.SecureFiles
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.StandardOpenOption

/**
 * JVM/Android [KeyringRepository]: `<localPath>/keystore/<user>/keyring.pmk`.
 *
 * It sits in the account's keystore directory next to the `.pfx`, `hybrid.key` and `mldsa.key`,
 * because those four artifacts share a fate — they are this device's identity for this account, they
 * are all excluded from sync bundles ([DirectoryBundler.syncExclusions]), and a user backing up one
 * of them has to back up all of them. Deliberately **not** in the `database/` directory: losing or
 * restoring the vault must not touch the keyring, which is the whole point of hanging the PQ key
 * files off the master key rather than off the vault.
 *
 * Writes use the same temp-file + rename + [SecureFiles] discipline as `HybridKeyManager.loadOrCreate`,
 * with two additions: the temp file is fsynced before the rename, and the rename goes through
 * [DurableFiles] rather than `File.renameTo` so it is atomic on Windows too and the parent directory
 * entry is fsynced afterwards. A keyring is the only copy of the key that opens everything else, so a
 * torn write is not a recoverable inconvenience the way a torn cache is — the ordering guarantee has
 * to survive a power cut, not just a process crash.
 */
class KeyringStore(private val platform: Platform) : KeyringRepository {

    override fun exists(username: String): Boolean = keyringFile(username).let { it.isFile && it.length() > 0 }

    override fun read(username: String): ByteArray? {
        val file = keyringFile(username)
        // A zero-length file is treated as absent, not as a corrupt keyring: that is what a crash
        // between `createNewFile` and the write in any older code path would leave behind, and
        // reporting it as "no keyring" lets the account bootstrap one instead of failing forever.
        if (!file.isFile || file.length() == 0L) return null
        return file.readBytes()
    }

    /**
     * Mint [username]'s first keyring, claiming the name with `O_EXCL`.
     *
     * `CREATE_NEW` is the whole substance of this method. Checking [exists] and then calling [write]
     * would leave a window in which a second login — a second *process*, on a desktop app with no
     * single-instance lock — mints its own master key, writes it, and re-keys the identity store
     * under it; the first login would then resume with its stale "no keyring" answer and overwrite
     * that keyring, leaving a `.pfx` sealed under a master key that exists nowhere. Both logins
     * report success and the account is gone. The kernel decides who wins instead.
     *
     * A `false` return therefore means "you lost, throw away the key you were about to install" and
     * never "try again with [write]".
     */
    override fun createNew(username: String, bytes: ByteArray): Boolean {
        require(bytes.isNotEmpty()) { "refusing to write an empty keyring" }
        val file = keyringFile(username)
        val directory = file.parentFile
        directory?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }

        val channel = try {
            FileChannel.open(file.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        } catch (_: FileAlreadyExistsException) {
            // Someone else holds the name. A zero-length file gets the same answer as a real one:
            // read() reports it as "no keyring", but reclaiming it here would need a check-then-write
            // that two racing minters could both pass, which is the exact hole this method closes.
            // Nothing in this codebase can produce that file — write() and this method both publish
            // complete content — so refusing is safe, and refusing loudly beats overwriting.
            check(file.length() > 0L) {
                "a zero-length ${DirectoryBundler.KEYRING_FILE_NAME} is in the way for $username; " +
                    "remove it by hand before signing in"
            }
            return false
        }

        var complete = false
        try {
            SecureFiles.ownerOnly(file) // owner-only before any key-bearing byte is written
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer) // write() is allowed to be short
            channel.force(true) // content and metadata on stable storage before we claim success
            complete = true
        } finally {
            channel.close()
            // A failed mint must not leave the husk that the branch above refuses to touch.
            if (!complete) file.delete()
            DurableFiles.syncDirectory(directory)
        }
        return true
    }

    override fun write(username: String, bytes: ByteArray) = writeDurably(keyringFile(username), bytes)

    override fun delete(username: String): Boolean = keyringFile(username).delete()

    override fun writeNext(username: String, bytes: ByteArray) = writeDurably(stagedFile(username), bytes)

    override fun readNext(username: String): ByteArray? {
        val file = stagedFile(username)
        // Zero length is "no pending change", for the same reason it is "no keyring" above: it is
        // what a crash between create and write leaves, and promoting it would destroy the account.
        if (!file.isFile || file.length() == 0L) return null
        return file.readBytes()
    }

    override fun promoteNext(username: String): Boolean {
        val staged = stagedFile(username)
        if (!staged.isFile || staged.length() == 0L) return false
        val live = keyringFile(username)
        // A move, not a copy-then-delete: the live keyring must never be absent, and a promotion that
        // half-copied would leave a keyring nothing can unwrap where the only good one used to be.
        DurableFiles.replace(staged, live)
        SecureFiles.ownerOnly(live)
        return true
    }

    override fun deleteNext(username: String): Boolean = stagedFile(username).delete()

    private fun writeDurably(file: File, bytes: ByteArray) {
        require(bytes.isNotEmpty()) { "refusing to write an empty keyring" }
        val directory = file.parentFile
        directory?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }

        // The temp lives in the account directory because the rename that follows has to stay on one
        // filesystem, and that directory is one this device *bundles* for a paired peer. A power cut
        // between the write below and the rename therefore leaves a file full of wrapped master key
        // sitting inside a sync source. `DirectoryBundler.syncExclusions` cannot cover it — those are
        // exact basenames and this one carries a random infix — so the bundler filters
        // `DirectoryBundler.TEMP_FILE_SUFFIX` by pattern in both directions instead. Renaming the
        // suffix here without changing that filter puts key material back on the wire.
        val tmp = File.createTempFile("${file.name}.", DirectoryBundler.TEMP_FILE_SUFFIX, directory)
        SecureFiles.ownerOnly(tmp) // owner-only before any key-bearing byte is written
        try {
            tmp.outputStream().use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync() // the rename is only meaningful if the content reached stable storage
            }
            // Not `renameTo` + delete-then-retry: that branch is the *normal* path on Windows, where
            // a rename onto an existing name fails, and it leaves the keyring under neither name
            // until the retry lands. DurableFiles.replace never unlinks the target as a separate
            // step, and fsyncs the directory so the swap itself survives a power cut.
            DurableFiles.replace(tmp, file)
        } finally {
            tmp.delete()
        }
        SecureFiles.ownerOnly(file)
    }

    private fun keyringFile(username: String): File =
        accountFile(username, DirectoryBundler.KEYRING_FILE_NAME)

    private fun stagedFile(username: String): File =
        accountFile(username, DirectoryBundler.KEYRING_STAGED_FILE_NAME)

    private fun accountFile(username: String, name: String): File =
        File("${platform.getLocalPath()}/keystore/$username/$name")
}
