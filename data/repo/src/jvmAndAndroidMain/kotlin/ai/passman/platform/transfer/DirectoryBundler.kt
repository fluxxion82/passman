package ai.passman.platform.transfer

import ai.passman.crypto.io.DurableFiles
import ai.passman.keystore.KeystoreClient
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.concurrent.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
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
    ) = withDestinationLock(destDir) {
        unbundleLocked(bundleBytes, destDir, excludeBaseNames, maxEntries, maxTotalBytes)
    }

    /**
     * Serialises unbundles per destination directory.
     *
     * Two unbundles into one directory are reachable: two peers pushing the same artifact at once
     * (the receive server registers plain Ktor routes and serialises nothing), or a peer's push
     * overlapping a locally started pull. They would otherwise share one staging directory — its
     * name is derived from the destination — and the second one's entry-time wipe would delete the
     * first one's extracted files mid-flight, leaving the first to commit a file the second is
     * still writing. Renaming a half-written ring over a live one is the exact outcome the staging
     * directory exists to prevent.
     *
     * A plain lock rather than a Mutex because this function is not suspending and every caller is
     * already on an IO dispatcher doing blocking file work. Keyed on the canonical path so two
     * File objects naming one directory share a lock; the map holds one entry per artifact
     * directory per account, which is a handful for the life of the process.
     */
    private fun <T> withDestinationLock(destDir: File, body: () -> T): T {
        val key = runCatching { destDir.canonicalFile.path }.getOrElse { destDir.path }
        return destinationLocks.computeIfAbsent(key) { ReentrantLock() }.withLock(body)
    }

    private val destinationLocks = ConcurrentHashMap<String, ReentrantLock>()

    private fun unbundleLocked(
        bundleBytes: ByteArray,
        destDir: File,
        excludeBaseNames: Set<String>,
        maxEntries: Int,
        maxTotalBytes: Long,
    ) {
        destDir.mkdirs()
        val destRoot = destDir.canonicalFile.toPath()
        val excludedResolvedNames = excludeBaseNames.mapTo(HashSet()) { it.lowercase() }
        var entries = 0
        var total = 0L

        // Extract to a staging directory first, and only move files into place once the whole
        // bundle has been read. Writing straight to the final paths meant a bundle that failed
        // partway - the size caps below throw from *inside* an open output stream - left the
        // previous entries committed and the current one truncated. That is not a visible failure
        // afterwards: a truncated PGP ring is silently skipped by the key listing, so the key just
        // disappears, and a truncated keystore still lists (getAllKeystores filters by extension,
        // it does not parse) and fails later looking like a wrong password.
        //
        // A SIBLING of destDir, never a child: this same object bundles destDir, so staging inside
        // it would make the half-written copies candidates for the next outbound bundle. Sibling
        // also keeps staging on the same filesystem, which is what lets the commit below be an
        // atomic rename rather than a copy.
        val staging = sibling(destDir, UNBUNDLE_STAGING_SUFFIX)
        staging.deleteRecursively()
        staging.mkdirs()

        try {
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
                val staged = File(staging, safeRelative)
                if (entry.isDirectory) {
                    staged.mkdirs()
                } else {
                    staged.parentFile?.mkdirs()
                    staged.outputStream().use { out ->
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

            // Every entry read and validated. Commit each file with an atomic rename, so a file
            // in destDir is either its old contents or its new contents and never a prefix of the
            // new ones. This is a merge into an existing directory rather than a replacement of
            // it, so per-file atomicity is the guarantee on offer: nothing lands unless the whole
            // bundle validated, and each file that lands, lands whole.
            staging.walkTopDown()
                .filter { it.isFile }
                .forEach { source ->
                    val relative = source.relativeTo(staging).path
                    val target = File(destDir, relative)
                    // Unchanged is the common case by far, and skipping BOTH steps is the point:
                    // rewriting a file with its own bytes still opens a window for a foreground
                    // write to land and be overwritten, and the preserve would have found nothing
                    // displaced to save. Nearly every file in every bundle takes this path.
                    if (isUnchanged(target, source)) return@forEach
                    target.parentFile?.mkdirs()
                    preserveDisplaced(target, destDir, relative)
                    DurableFiles.replace(source, target)
                }
        } finally {
            staging.deleteRecursively()
        }
    }

    /**
     * Suffix for the staging directory [unbundle] extracts into. Distinct from [TEMP_FILE_SUFFIX],
     * which names transient *files inside* an artifact directory; this names a whole directory
     * beside one.
     */
    private const val UNBUNDLE_STAGING_SUFFIX = ".unbundle-staging"

    /**
     * Sibling of the artifact directory holding every version sync has displaced.
     *
     * A SIBLING, never a child, and that placement is the whole design. [bundle] walks every
     * descendant of the directory it is given, so a preserved secret ring stored inside the artifact
     * directory would be pushed to the peer on the next sync — a local safety copy turned into a
     * key-material leak. Being outside also puts it beyond the canonical-path confinement in
     * [unbundle], so no crafted zip entry can reach it, and outside both artifact listings, which
     * read only the artifact directory. That is why this design needs no filter at any bundle or
     * unbundle call site and no change to any listing: the location does the work a filter would
     * have had to do at eight places without ever being missed at one of them.
     */
    fun conflictStore(destDir: File): File = sibling(destDir, CONFLICT_STORE_SUFFIX)

    /**
     * `<destDir><suffix>`, resolved as a true **sibling** of [destDir].
     *
     * Both scratch directories this bundler keeps — staging and the conflict store — must sit
     * outside the tree being bundled, because [bundle] walks every descendant of its root and would
     * otherwise ship their contents to a peer. `absoluteFile` first is what makes that hold: a
     * single-segment relative path has a null parent, and the obvious `?: destDir` fallback then
     * places the directory *inside* the very tree it must stay out of, failing toward the leak.
     */
    private fun sibling(destDir: File, suffix: String): File {
        val resolved = destDir.absoluteFile
        val parent = requireNotNull(resolved.parentFile) { "artifact directory has no parent: $destDir" }
        return File(parent, "${resolved.name}$suffix")
    }

    /** Every version sync has displaced for [destDir], newest first. For the recovery UI. */
    fun preservedCopies(destDir: File): List<File> =
        conflictStore(destDir).listFiles()
            .orEmpty()
            .filter { it.isFile }
            .sortedByDescending { it.lastModified() }

    /**
     * Distinct from [UNBUNDLE_STAGING_SUFFIX], which names a directory that is wiped on every
     * unbundle. This one is never wiped by anything except the user.
     */
    private const val CONFLICT_STORE_SUFFIX = ".conflicts"

    /**
     * Cap for a conflict filename, in UTF-8 bytes. Filesystems typically stop at 255; the margin
     * covers the ones that do not.
     *
     * A nested entry flattens its whole path into one filename, so a path with legal components can
     * still exceed the limit. Without this cap the rename throws, and because the throw happens
     * before the replace the live file survives — but the unbundle aborts partway through its
     * commit loop, and it aborts again on every later sync carrying different bytes for that path.
     * A peer could wedge a directory's sync permanently, with nothing in the app to explain it.
     */
    private const val MAX_CONFLICT_NAME_BYTES = 200

    /** 128 bits: a collision here would put two different secret rings on one name. */
    private const val DIGEST_BYTES = 16

    /**
     * Names the file a preserve renames the live artifact onto before it knows what to call it.
     *
     * Readable on purpose: if the process dies between the capture and the final rename, this file
     * is left holding real key material, and [preservedCopies] deliberately still lists it. An
     * awkward name in the recovery list beats a secret ring hidden behind a name that looks like
     * scratch.
     */
    private const val CAPTURE_PREFIX = "preserving-"
    private const val CAPTURE_SUFFIX = ".partial"

    /** True when [live] already holds exactly what [incoming] would write. */
    internal fun isUnchanged(live: File, incoming: File): Boolean =
        live.isFile &&
            live.length() == incoming.length() &&
            live.readBytes().contentEquals(incoming.readBytes())

    /**
     * Moves [live] into [destDir]'s conflict store, where [relative] is its path within the bundle.
     *
     * **A rename, never a copy, and that is the design rather than a detail.** Copy-then-replace
     * preserves a snapshot taken at inspection time, which loses any write landing in between — and
     * writes do land in between, because push-receive is a background server while key edits are
     * foreground UI, and both `addSubKey` and `changeKeyPassword` rewrite the live path directly.
     * Renaming preserves whatever is actually there at the instant it is displaced, and fails in the
     * right direction: if it cannot happen, this throws and the caller never replaces anything.
     *
     * The store is derived from [destDir] — the directory being unbundled, and the value the
     * per-destination lock is keyed on — never from the live file's own parent. For a nested entry
     * the latter yields `destDir/sub.conflicts`, a **child** of the bundled tree, which the next
     * outbound bundle would ship to every peer: a local safety copy turned into a key-material leak.
     *
     * Honest about what this does not buy: a foreground writer can still recreate the live path in
     * the window between this rename and the caller's replace, and that write is then overwritten
     * unpreserved. Closing it needs a lock shared with every writer, not just with unbundle.
     */
    private fun preserveDisplaced(live: File, destDir: File, relative: String) {
        if (!live.isFile) return

        val store = conflictStore(destDir).apply { mkdirs() }

        // Capture first, inspect second — the order is the whole correctness argument.
        //
        // Reading the live file to decide what to do and *then* acting on that same path is how
        // bytes get lost: a foreground key edit can publish a new version in between, and the
        // action is applied to bytes nobody ever looked at. That is not hypothetical — the PGP
        // writer publishes secret rings by atomic rename onto exactly this path. An earlier
        // version of this function ended its equality branch with `live.delete()`, which meant a
        // version that landed in that window was deleted having never been preserved.
        //
        // This rename is atomic, so it takes whatever is genuinely there at that instant. Every
        // decision after it is made about a file inside the store, at a path no other writer knows.
        val captured = Files.createTempFile(store.toPath(), CAPTURE_PREFIX, CAPTURE_SUFFIX).toFile()
        DurableFiles.replace(live, captured)

        val bytes = captured.readBytes()
        val preserved = File(store, conflictName(bytes, relative))
        if (preserved.isFile && preserved.readBytes().contentEquals(bytes)) {
            // This exact version is already in the store. Verified byte for byte rather than
            // inferred from the name, because the name carries a digest and trusting a name match
            // would let a collision drop the only copy of a ring. Deleting is safe here in a way it
            // never was on the live path: this file is one this call created and nothing else can
            // reach it.
            captured.delete()
            return
        }
        DurableFiles.replace(captured, preserved)
    }

    /**
     * `<path>.<digest>.<ext>` — the original name stays legible while the digest keeps it unique.
     *
     * The bundle-relative path is folded in, so `a/x` and `b/x` cannot land on one name in the flat
     * store. 128 bits of digest, not 64: a collision here means one preserved secret ring silently
     * replaces another, and the verify above turns that from destruction into a duplicate only if
     * the bytes really match.
     */
    private fun conflictName(displaced: ByteArray, relative: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(displaced)
            .take(DIGEST_BYTES)
            .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }
        // Budget what is left after the digest, which must survive intact. Truncating the readable
        // half costs nothing: the digest is what makes the name unique, so two entries sharing a cut
        // prefix still separate unless their bytes match — and matching bytes are the one case where
        // sharing a name is correct.
        val budget = MAX_CONFLICT_NAME_BYTES - digest.length - 1
        return "$digest-${encodeRelative(relative).takeUtf8Bytes(budget)}"
    }

    /**
     * The bundle-relative path a preserved copy was displaced from, for display and for restore.
     *
     * Recovering it has to be exact, because restoring a copy means putting it back where it came
     * from. That is why [encodeRelative] escapes separators reversibly instead of flattening them to
     * underscores, and why the digest leads: it is a fixed 32 hex characters with no `-`, so the
     * first `-` is unambiguously the separator no matter what the path contains.
     *
     * Returns the whole name if it does not parse — a hand-copied file in the store is still a file
     * worth showing, and inventing a path for it would be worse than admitting the name is all there
     * is.
     */
    fun originalPathOf(preserved: File): String {
        val name = preserved.name
        val separator = name.indexOf('-')
        if (separator != DIGEST_BYTES * 2) return name
        return decodeRelative(name.substring(separator + 1))
    }

    /**
     * Escapes a bundle-relative path into a single filename, reversibly.
     *
     * `%` first, then the separator, so that decoding in the mirror order round-trips a path that
     * genuinely contains the escape sequence: `a%2Fb` encodes to `a%252Fb`, which decodes back to
     * `a%2Fb` rather than to `a/b`.
     */
    private fun encodeRelative(relative: String): String = relative
        .replace(File.separatorChar, '/')
        .replace("%", "%25")
        .replace("/", "%2F")

    private fun decodeRelative(encoded: String): String = encoded
        .replace("%2F", "/")
        .replace("%25", "%")

    /**
     * Longest prefix of this string whose UTF-8 encoding fits [maxBytes], cut on a char boundary.
     *
     * Bytes rather than characters because that is what the filesystem limits, and these names come
     * from peer-authored zip entries, which may be any UTF-8 at all.
     */
    private fun String.takeUtf8Bytes(maxBytes: Int): String {
        if (maxBytes <= 0) return ""
        var used = 0
        val out = StringBuilder()
        for (character in this) {
            val size = character.toString().toByteArray(Charsets.UTF_8).size
            if (used + size > maxBytes) break
            out.append(character)
            used += size
        }
        return out.toString()
    }

    class BundleTooLargeException(message: String) : Exception(message)
}
