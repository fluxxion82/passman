package ai.passman.platform.transfer

import ai.passman.keystore.KeystoreClient
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

object DirectoryBundler {
    const val HYBRID_KEY_FILE_NAME = "hybrid.key"
    const val ML_DSA_KEY_FILE_NAME = "mldsa.key"

    /**
     * The device keyring. It wraps this device's master key, from which the identity-store password
     * and every key-file key are derived, so it is device identity in the strictest sense — bundling
     * it would hand a peer the ability to open this device's `.pfx` and key files, and unbundling a
     * peer's copy would replace the local master key and orphan everything sealed under it.
     *
     * Declared here rather than in `KeyringStore` so the exclusion can never drift from the filename:
     * the store imports this constant.
     */
    const val KEYRING_FILE_NAME = "keyring.pmk"

    /**
     * The pending keyring generation a password change stages before it commits the new credential.
     *
     * It holds the *same* device master key as [KEYRING_FILE_NAME], just wrapped under a different
     * password, so every reason the live keyring is excluded applies to it unchanged — and one more:
     * a peer's staged generation unbundled over this device's would be promoted by the next login and
     * would replace the live keyring with a master key from another machine.
     */
    const val KEYRING_STAGED_FILE_NAME = "$KEYRING_FILE_NAME.next"

    /**
     * The keyring-sealed record that lets a signed-in app open the portable-recovery P12 — the
     * recovery password (a BIP39 phrase) plus the pin of the certificate it belongs to, sealed under
     * this device's master key (`KeyFileEnvelope`, purpose `RECOVERY_PASSWORD`).
     *
     * Device-sealed means a peer's copy is ciphertext the receiving keyring can never open, so
     * unbundling one over the local record does not corrupt anything visibly — it silently replaces
     * the receiver's working recovery record with an unopenable one, and the breakage surfaces only
     * at the worst possible time, when the user actually needs their recovery phrase. Outbound it is
     * sealed and therefore not a leak, but it is meaningless to every other device, and both
     * directions have to filter it for the same reason the keyring itself is filtered.
     *
     * Declared here rather than in `JvmPortableVaultRecovery` for the same reason as
     * [KEYRING_FILE_NAME]: the writer imports this constant, so the exclusion can never drift from
     * the filename.
     */
    const val PORTABLE_RECOVERY_RECORD_FILE_NAME = "portable-recovery.pmk"

    /**
     * The pre-upgrade recovery P12 the phrase upgrade keeps while it swaps the replacement in, and
     * deliberately strands when both the swap and the restore fail — the same crash-debris shape as
     * the identity-store backup, for the same reason. Outbound it is a complete (password-encrypted)
     * copy of this device's recovery private key sitting in a sync source; inbound is worse than
     * debris, because the legacy-open path in `JvmPortableVaultRecovery.open` will try to *restore*
     * whatever sits at this name over the live P12.
     */
    const val PORTABLE_RECOVERY_BACKUP_FILE_NAME = "portable-recovery.previous"

    /**
     * The portable-recovery P12 and its exported certificate, `<user>.recovery.p12` /
     * `<user>.recovery.crt`. Each device generates its own recovery keypair, so neither file means
     * anything on another machine: a foreign P12 fails the local record's certificate pin (and its
     * password), and on a device that has not created recovery material yet the mere presence of
     * either file wedges creation permanently — `JvmPortableVaultRecovery.create` refuses to run
     * while one exists, because a partial set is indistinguishable from a half-destroyed one.
     * The P12 is also the sender's recovery private key, which has no business on the wire even
     * encrypted. `JvmPortableVaultRecovery` builds its filenames from these functions, so the writer
     * and the filter cannot drift apart.
     */
    fun portableRecoveryP12Name(userName: String): String = "$userName.recovery.p12"

    fun portableRecoveryCertificateName(userName: String): String = "$userName.recovery.crt"

    /**
     * Publishing temp files are filtered by pattern, in both directions, on top of [syncExclusions].
     *
     * Every durable writer under `keystore/<user>/` — `KeyringStore.writeDurably`, and the key
     * managers — creates its temp file *inside* the directory it is publishing into, because the
     * rename that follows has to stay within one filesystem. `keystore/<user>/` is exactly the
     * directory this object bundles, so a power cut between the write and the rename leaves a temp
     * behind holding key-bearing bytes, and the next sync would ship it to a paired peer.
     *
     * [syncExclusions] cannot catch it: those entries are exact basenames, and a temp name carries a
     * random infix (`keyring.pmk.5481093.tmp`). Hence a suffix rule rather than another constant. A
     * `.tmp` file is by construction the residue of an interrupted write and is never worth syncing,
     * so filtering the whole suffix costs nothing.
     */
    const val TEMP_FILE_SUFFIX = ".tmp"

    /**
     * Every file an identity-store commit can leave in `keystore/<user>/`, and nothing else may.
     *
     * `JvmKeyStoreClient.commitIdentityStore` writes into the directory this object bundles, and it
     * creates exactly three kinds of file besides the store itself:
     *
     * 1. `<user>.pfx.<random>[TEMP_FILE_SUFFIX]` — the replacement, before it is proved good. Caught
     *    by the [TEMP_FILE_SUFFIX] rule, which exists precisely because the random infix makes an
     *    exact-basename set useless against it.
     * 2. `<user>.pfx[KeystoreClient.IDENTITY_STORE_BACKUP_SUFFIX]` — the recovery copy, kept while the
     *    replacement is swapped in and stranded on purpose when both the swap and the restore fail.
     *    Caught by the exact entry below.
     * 3. `<user>.pfx[KeystoreClient.IDENTITY_STORE_LOCK_SUFFIX]` — the advisory lock a commit and a
     *    backup recovery meet on, created empty on the first commit and deliberately never deleted
     *    (unlinking a lock file another process holds open leaves the two of them locking different
     *    inodes, which is no lock at all). Caught by the exact entry below.
     *
     * That is the complete list, which is the only reason exact names plus one suffix rule are a proof
     * rather than a hope. The backup used to be `<user>.pfx.<random>.bak` and matched neither rule: a
     * single interrupted commit left a **complete, openable copy of the device's RSA identity** beside
     * the store, and the next keystore sync put it on the wire. Making the name deterministic is what
     * makes the exclusion expressible at all. The lock file holds no bytes, so it is debris rather
     * than a leak — but a list with one member missing is not a list anybody can check the writer
     * against, which is the property this whole set is here for.
     *
     * The constants are imported from `data:keystore` rather than declared here — the dependency runs
     * that way — so the writer and the filter cannot drift apart.
     */
    private fun identityStoreBackupName(userName: String): String =
        KeystoreClient.identityStoreBackupName("$userName.pfx")

    private fun identityStoreLockName(userName: String): String =
        KeystoreClient.identityStoreLockName("$userName.pfx")

    fun syncExclusions(userName: String): Set<String> = setOf(
        "$userName.pfx",
        identityStoreBackupName(userName),
        identityStoreLockName(userName),
        HYBRID_KEY_FILE_NAME,
        ML_DSA_KEY_FILE_NAME,
        KEYRING_FILE_NAME,
        KEYRING_STAGED_FILE_NAME,
        PORTABLE_RECOVERY_RECORD_FILE_NAME,
        PORTABLE_RECOVERY_BACKUP_FILE_NAME,
        portableRecoveryP12Name(userName),
        portableRecoveryCertificateName(userName),
    )

    /**
     * Zips every file under [sourceDir] except those whose basename matches an entry in
     * [excludeBaseNames] or ends in [TEMP_FILE_SUFFIX]. Use the exclusion list to keep
     * device-identity files (e.g. the user's primary login keystore `${userName}.pfx`) out of the
     * wire bundle - syncing those would clobber the peer's RSA keypair and break decryption of its
     * existing data.
     */
    fun bundle(sourceDir: File, excludeBaseNames: Set<String> = emptySet()): ByteArray {
        require(sourceDir.isDirectory) { "not a directory: $sourceDir" }
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            sourceDir.walkTopDown()
                .filter { it.isFile && it.name !in excludeBaseNames && !it.name.endsWith(TEMP_FILE_SUFFIX) }
                .forEach { file ->
                    val entryName = file.relativeTo(sourceDir).invariantSeparatorsPath
                    zip.putNextEntry(ZipEntry(entryName))
                    file.inputStream().use { it.copyTo(zip) }
                    zip.closeEntry()
                }
        }
        return out.toByteArray()
    }

    /**
     * Unzips into [destDir]. Entries whose basename matches an entry in [excludeBaseNames], or ends
     * in [TEMP_FILE_SUFFIX], are skipped - belt-and-suspenders defense in case a hostile / older peer
     * didn't filter on push.
     *
     * The basename is compared as the destination filesystem will resolve it, not as the zip spells
     * it: the filesystems desktop ships to — APFS and NTFS in their default configurations — are
     * case-insensitive, so `Alice.recovery.p12` opens the very file `alice.recovery.p12` names, and
     * NTFS additionally strips trailing dots and spaces at open, folding `alice.pfx.` onto
     * `alice.pfx`. An exact match would let a hostile or case-mangled entry walk straight through
     * the exclusion set onto the excluded file, so both sides of the comparison are lowercased and
     * the entry's basename is trimmed of trailing `.` and ` ` first. [bundle] stays exact: its names
     * are generated locally from the same username the exclusions are, never by a peer.
     *
     * DoS-hardened: caps the entry count ([maxEntries]) and the total uncompressed bytes
     * ([maxTotalBytes], zip-bomb defense), and confines every write to [destDir] by canonical path
     * (traversal / symlink-escape defense). Exceeding a cap throws [BundleTooLargeException]; the
     * caller treats a failed unbundle as a rejected push.
     */
    fun unbundle(
        bundleBytes: ByteArray,
        destDir: File,
        excludeBaseNames: Set<String> = emptySet(),
        maxEntries: Int = 1_024,
        maxTotalBytes: Long = 50L * 1024 * 1024,
    ) {
        destDir.mkdirs()
        val destRoot = destDir.canonicalFile.toPath()
        val excludedResolvedNames = excludeBaseNames.mapTo(HashSet()) { it.lowercase() }
        var entries = 0
        var total = 0L
        ZipInputStream(bundleBytes.inputStream()).use { zip ->
            var entry: ZipEntry? = zip.nextEntry
            while (entry != null) {
                if (++entries > maxEntries) {
                    throw BundleTooLargeException("bundle has more than $maxEntries entries")
                }
                val safeRelative = entry.name.replace('\\', '/')
                // The name the destination filesystem would resolve the entry to — see the KDoc.
                val resolvedBaseName = File(safeRelative).name.trimEnd('.', ' ').lowercase()
                if (safeRelative.contains("..") ||
                    resolvedBaseName in excludedResolvedNames ||
                    resolvedBaseName.endsWith(TEMP_FILE_SUFFIX)
                ) {
                    entry = zip.nextEntry
                    continue
                }
                val target = File(destDir, safeRelative)
                // Confine to destDir: a crafted entry name must not resolve outside the root.
                if (!target.canonicalFile.toPath().startsWith(destRoot)) {
                    entry = zip.nextEntry
                    continue
                }
                if (entry.isDirectory) {
                    target.mkdirs()
                } else {
                    target.parentFile?.mkdirs()
                    target.outputStream().use { out ->
                        val buffer = ByteArray(8_192)
                        var read = zip.read(buffer)
                        while (read >= 0) {
                            total += read
                            if (total > maxTotalBytes) {
                                throw BundleTooLargeException("bundle exceeds $maxTotalBytes uncompressed bytes")
                            }
                            out.write(buffer, 0, read)
                            read = zip.read(buffer)
                        }
                    }
                }
                zip.closeEntry()
                entry = zip.nextEntry
            }
        }
    }

    class BundleTooLargeException(message: String) : Exception(message)
}
