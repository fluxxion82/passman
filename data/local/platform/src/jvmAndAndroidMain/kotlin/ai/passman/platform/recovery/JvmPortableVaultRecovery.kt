package ai.passman.platform.recovery

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.crypto.io.DurableFiles
import ai.passman.crypto.keyring.KeyFileEnvelope
import ai.passman.crypto.keyring.KeyFilePurpose
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.model.PortableVaultRecoveryFormat
import ai.passman.keystore.LowPbePkcs12Writer
import ai.passman.keystore.Pkcs12Certificates
import ai.passman.platform.crypto.SecureRandomService
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.io.SecureFiles
import java.io.ByteArrayInputStream
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Per-profile user-owned recovery P12 and the small keyring-sealed record that lets a signed-in app
 * use it.  The recovery password is random data, never the login password.
 */
class JvmPortableVaultRecovery(
    private val platform: Platform,
    private val random: SecureRandomService,
) {
    fun access(username: String, sessionKey: VaultSessionKey): PortableVaultAccess {
        val opened = material(username, sessionKey)
        return access(username, opened)
    }

    /**
     * Explicitly converts a version-one Base64URL recovery password into a 24-word BIP39 phrase.
     * The recovery RSA key and certificate are intentionally preserved, so the CMS vault is not
     * re-encrypted and remains readable through the replacement P12.
     */
    fun upgrade(username: String, sessionKey: VaultSessionKey): PortableVaultAccess =
        ArtifactDirectoryLock.withLock(directory(username)) { upgradeLocked(username, sessionKey) }

    /**
     * Held across the whole upgrade, not just each write. It strands the previous P12 deliberately
     * when both the swap and the restore fail, so a sync landing between the backup and the
     * replacement would leave the two halves describing different keys.
     */
    private fun upgradeLocked(username: String, sessionKey: VaultSessionKey): PortableVaultAccess {
        val current = material(username, sessionKey)
        if (current.format == PortableVaultRecoveryFormat.Bip39English24) {
            return access(username, current)
        }

        val phrase = Bip39RecoveryPhrase.generate(random)
        val replacement = LowPbePkcs12Writer.encode(
            ALIAS,
            current.privateKey,
            listOf(current.certificate),
            phrase.toCharArray(),
        )
        try {
            verifyP12(replacement, phrase, current.certificate)
            val previous = p12File(username).readBytes()
            try {
                writeAtomically(username, backupFile(username), previous)
            } finally {
                previous.fill(0)
            }

            try {
                writeAtomically(username, p12File(username), replacement)
                writeRecord(username, phrase, PortableVaultRecoveryFormat.Bip39English24, current.certificate, sessionKey)
            } catch (failure: Throwable) {
                restoreBackup(username, current.password, current.certificate)
                throw failure
            }
            backupFile(username).delete()
            return access(username, sessionKey)
        } finally {
            replacement.fill(0)
        }
    }

    private fun access(username: String, opened: RecoveryKeyMaterial): PortableVaultAccess =
        PortableVaultAccess(
            profileDirectory = directory(username).absolutePath,
            pkcs12Path = p12File(username).absolutePath,
            certificatePath = certificateFile(username).absolutePath,
            vaultPath = vaultFile(username).absolutePath,
            recoveryPassword = opened.password,
            recoveryFormat = opened.format,
        )

    /**
     * Deliberately **not** locked here, and that is a correction rather than an omission.
     *
     * An earlier version wrapped this whole dispatch, which read well and was wrong: this is the hot
     * path. `JvmPortableCmsVaultFormat.seal`/`open` call it on **every portable vault read and
     * write**, so locking here put a cross-process `FileLock` acquisition on every password save —
     * and, worse, made a save able to fail with `ArtifactDirectoryBusyException` while a sync held
     * the directory. Neither the ordinary open nor the common case writes anything.
     *
     * The two things that wrap bought are kept, moved to the paths that actually write: [create]
     * re-checks under its own lock so a concurrent first creation resolves instead of throwing, and
     * [restoreBackup] — the one part of [open] that writes — takes the lock itself.
     */
    internal fun material(username: String, sessionKey: VaultSessionKey): RecoveryKeyMaterial =
        if (materialFile(username).isFile) open(username, sessionKey) else create(username, sessionKey)

    internal fun open(username: String, sessionKey: VaultSessionKey): RecoveryKeyMaterial {
        // Fail closed, but name the cause: the record is sealed under this device's master key, so
        // "authentication failed" here almost always means the record is another device's — a
        // keystore sync from before DirectoryBundler excluded the recovery artifacts replaced it
        // (and the P12/certificate beside it) with the peer's copies, which this device can never
        // open. A bare envelope failure points an operator at nothing.
        val record = try {
            KeyFileEnvelope.open(materialFile(username).readBytes(), KeyFilePurpose.RECOVERY_PASSWORD, sessionKey)
        } catch (failure: Exception) {
            throw IllegalStateException(
                "cannot open ${materialFile(username).name} for $username: the record is sealed under this " +
                    "device's master key and this copy does not open. Most likely a keystore sync from before " +
                    "the recovery-file exclusions replaced it — along with ${p12File(username).name} and " +
                    "${certificateFile(username).name} — with a peer's device-sealed copies. Recovery for this " +
                    "profile stays broken until those files are removed from ${directory(username)}; removing " +
                    "all three lets the next access create fresh recovery material.",
                failure,
            )
        }
        val decoded = decodeRecord(record)
        record.fill(0)
        return try {
            val keyStore = try {
                keyStore(p12File(username), decoded.password)
            } catch (failure: Throwable) {
                if (decoded.format != PortableVaultRecoveryFormat.LegacyBase64Url || !backupFile(username).isFile) {
                    throw failure
                }
                restoreBackup(username, decoded.password, decoded.certificateFingerprint)
            }
            val certificate = keyStore.getCertificate(ALIAS) as? X509Certificate
                ?: error("portable recovery P12 has no certificate")
            check(MessageDigest.getInstance("SHA-256").digest(certificate.encoded).contentEquals(decoded.certificateFingerprint)) {
                "portable recovery certificate does not match its keyring pin"
            }
            val privateKey = keyStore.getKey(ALIAS, decoded.password.toCharArray()) as? PrivateKey
                ?: error("portable recovery P12 has no private key")
            RecoveryKeyMaterial(decoded.password, decoded.format, privateKey, certificate)
        } finally {
            decoded.certificateFingerprint.fill(0)
        }
    }

    private fun create(username: String, sessionKey: VaultSessionKey): RecoveryKeyMaterial =
        ArtifactDirectoryLock.withLock(directory(username)) { createLocked(username, sessionKey) }

    /**
     * Held across the whole creation — **including the RSA key generation**, which is deliberate and
     * is the opposite of what `JvmKeyStoreClient.createKeyStore` does a module away.
     *
     * The difference is that this method *reads* the directory to decide. The `exists()` check below
     * refuses to run while either file is present — a partial set is indistinguishable from a
     * half-destroyed one — so the decision and the writes have to be one critical section, and the
     * keygen sits between them. `createKeyStore` reads nothing, so it can build its store first and
     * lock only for the write, which is why its comment says holding the lock across a keygen buys
     * nothing; here it buys the atomicity of the check.
     *
     * The cost is real and bounded: an inbound sync arriving during a first recovery creation waits
     * out a 3072-bit keygen and may exhaust its budget, in which case the push is rejected and the
     * peer retries. It happens once per account, ever.
     */
    private fun createLocked(username: String, sessionKey: VaultSessionKey): RecoveryKeyMaterial {
        // Re-evaluated under the lock, because `material` decides outside it. Two concurrent first
        // accesses both take the create branch; the winner completes the whole set, and without this
        // the loser reached the check below, found the files present and threw — a hard failure on an
        // ordinary login. The check itself stays exactly as strict: a half-present set really is
        // indistinguishable from a half-destroyed one. What changed is that a *complete* set is now
        // recognised as the other caller's success and simply opened.
        if (materialFile(username).isFile) return open(username, sessionKey)
        check(!p12File(username).exists() && !certificateFile(username).exists()) {
            "portable recovery material is incomplete for $username"
        }
        val password = Bip39RecoveryPhrase.generate(random)
        try {
            val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(RSA_BITS) }.generateKeyPair()
            val certificate = Pkcs12Certificates.selfSignedRsa(keyPair, "Passman portable recovery $username")
            val p12 = LowPbePkcs12Writer.encode(ALIAS, keyPair.private, listOf(certificate), password.toCharArray())
            writeAtomically(username, p12File(username), p12)
            p12.fill(0)
            writeAtomically(username, certificateFile(username), pem(certificate).encodeToByteArray())
            val verified = keyStore(username, password)
            check(verified.getKey(ALIAS, password.toCharArray()) is PrivateKey) { "recovery P12 verification failed" }
            writeRecord(username, password, PortableVaultRecoveryFormat.Bip39English24, certificate, sessionKey)
            return RecoveryKeyMaterial(password, PortableVaultRecoveryFormat.Bip39English24, keyPair.private, certificate)
        } catch (failure: Throwable) {
            // Do not delete a P12 after a failed post-write verification: preserving it is safer than
            // pretending a user's recovery key never existed.  The missing sealed record fails closed.
            throw failure
        }
    }

    private fun keyStore(username: String, password: String): KeyStore = keyStore(p12File(username), password)

    private fun keyStore(file: File, password: String): KeyStore {
        ensureBouncyCastle()
        return KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME).apply {
            file.inputStream().use { load(it, password.toCharArray()) }
        }
    }

    private fun keyStore(bytes: ByteArray, password: String): KeyStore {
        ensureBouncyCastle()
        return KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME).apply {
            ByteArrayInputStream(bytes).use { load(it, password.toCharArray()) }
        }
    }

    private fun verifyP12(p12: ByteArray, password: String, certificate: X509Certificate) {
        val keyStore = keyStore(p12, password)
        check(keyStore.getKey(ALIAS, password.toCharArray()) is PrivateKey) { "recovery P12 verification failed" }
        check((keyStore.getCertificate(ALIAS) as? X509Certificate)?.encoded?.contentEquals(certificate.encoded) == true) {
            "recovery P12 certificate changed during phrase upgrade"
        }
    }

    private fun writeRecord(
        username: String,
        password: String,
        format: PortableVaultRecoveryFormat,
        certificate: X509Certificate,
        sessionKey: VaultSessionKey,
    ) {
        val pin = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
        try {
            val record = encodeRecord(password, format, pin)
            val sealed = try {
                KeyFileEnvelope.seal(record, KeyFilePurpose.RECOVERY_PASSWORD, sessionKey)
            } finally {
                record.fill(0)
            }
            try {
                writeAtomically(username, materialFile(username), sealed)
            } finally {
                sealed.fill(0)
            }
        } finally {
            pin.fill(0)
        }
    }

    /**
     * Restores the verified pre-upgrade P12 if a replacement was written before its record.
     *
     * The only write reachable from [open], and a read-modify-write at that: the bytes published come
     * from the backup read here, so a sync landing in between would be reverted by the publish.
     * Locked at this level rather than by wrapping [open], which is the hot read path — see
     * [material].
     */
    private fun restoreBackup(username: String, password: String, expectedCertificate: X509Certificate): KeyStore =
        ArtifactDirectoryLock.withLock(directory(username)) {
            restoreBackupLocked(username, password, expectedCertificate)
        }

    private fun restoreBackupLocked(
        username: String,
        password: String,
        expectedCertificate: X509Certificate,
    ): KeyStore {
        val backup = backupFile(username)
        val keyStore = keyStore(backup, password)
        val certificate = keyStore.getCertificate(ALIAS) as? X509Certificate
            ?: error("portable recovery backup has no certificate")
        check(certificate.encoded.contentEquals(expectedCertificate.encoded)) { "portable recovery backup certificate mismatch" }
        val bytes = backup.readBytes()
        try {
            writeAtomically(username, p12File(username), bytes)
        } finally {
            bytes.fill(0)
        }
        backup.delete()
        return keyStore
    }

    private fun restoreBackup(username: String, password: String, expectedPin: ByteArray): KeyStore {
        val backup = backupFile(username)
        val keyStore = keyStore(backup, password)
        val certificate = keyStore.getCertificate(ALIAS) as? X509Certificate
            ?: error("portable recovery backup has no certificate")
        check(MessageDigest.getInstance("SHA-256").digest(certificate.encoded).contentEquals(expectedPin)) {
            "portable recovery backup certificate mismatch"
        }
        val bytes = backup.readBytes()
        try {
            writeAtomically(username, p12File(username), bytes)
        } finally {
            bytes.fill(0)
        }
        backup.delete()
        return keyStore
    }

    private fun pem(certificate: X509Certificate): String = buildString {
        append("-----BEGIN CERTIFICATE-----\n")
        append(Base64.getMimeEncoder(64, "\n".encodeToByteArray()).encodeToString(certificate.encoded))
        append("\n-----END CERTIFICATE-----\n")
    }

    private fun encodeRecord(password: String, format: PortableVaultRecoveryFormat, pin: ByteArray): ByteArray {
        val bytes = password.encodeToByteArray()
        require(bytes.size <= 255 && pin.size == PIN_BYTES)
        return byteArrayOf(recordVersion(format), bytes.size.toByte()) + bytes + pin
    }

    private fun decodeRecord(bytes: ByteArray): DecodedRecord {
        require(bytes.size >= 2 + PIN_BYTES) { "invalid portable recovery record" }
        val format = recordFormat(bytes[0]) ?: error("invalid portable recovery record")
        val passwordLength = bytes[1].toInt() and 0xFF
        require(bytes.size == 2 + passwordLength + PIN_BYTES) { "invalid portable recovery record length" }
        return DecodedRecord(
            password = bytes.copyOfRange(2, 2 + passwordLength).decodeToString(),
            format = format,
            certificateFingerprint = bytes.copyOfRange(2 + passwordLength, bytes.size),
        )
    }

    private fun recordVersion(format: PortableVaultRecoveryFormat): Byte = when (format) {
        PortableVaultRecoveryFormat.LegacyBase64Url -> LEGACY_RECORD_VERSION
        PortableVaultRecoveryFormat.Bip39English24 -> BIP39_RECORD_VERSION
    }

    private fun recordFormat(version: Byte): PortableVaultRecoveryFormat? = when (version) {
        LEGACY_RECORD_VERSION -> PortableVaultRecoveryFormat.LegacyBase64Url
        BIP39_RECORD_VERSION -> PortableVaultRecoveryFormat.Bip39English24
        else -> null
    }

    /**
     * Publish [bytes] at [target], holding **[username]'s account directory** lock.
     *
     * `keystore/<user>/` is a directory sync unbundles into, so every write here has to be ordered
     * against `unbundle`'s displace-then-install pair. Taken in this one method because every write
     * in this class funnels through it, which makes the wrap unmissable; the multi-file operations
     * take it again at their own level so their writes land as one, and it is reentrant.
     *
     * Keyed on `directory(username)`, never on `target.parentFile`, and the difference is not
     * theoretical: usernames are gated on trimmed length alone, so `team/a` is a legal account and
     * `p12File("team/a")` is `keystore/team/a/team/a.recovery.p12` — whose parent is
     * `keystore/team/a/team`, while sync locks `keystore/team/a`. Two different locks over one file
     * is no exclusion at all, and the stray lock file would have been created *inside* the directory
     * `bundle()` walks. The same "a name is really a path" shape as the keystore-name guard, arriving
     * this time through the username.
     *
     * What this does NOT fix is the matching hole in the exclusion list: `syncExclusions` compares
     * basenames, so for `team/a` it holds `team/a.recovery.p12` while the file's basename is
     * `a.recovery.p12`, and the P12 stays syncable in both directions. That is the same
     * compare-a-name-where-the-filesystem-resolves-a-path defect recorded against `syncExclusions`
     * itself, and it needs the canonical-path rework rather than a change here.
     */
    private fun writeAtomically(username: String, target: File, bytes: ByteArray) =
        ArtifactDirectoryLock.withLock(directory(username)) {
            writeAtomicallyLocked(target, bytes)
        }

    private fun writeAtomicallyLocked(target: File, bytes: ByteArray) {
        val parent = checkNotNull(target.parentFile)
        parent.mkdirs()
        SecureFiles.ownerOnlyDir(parent)
        val temporary = File.createTempFile("${target.name}.", ".tmp", parent)
        SecureFiles.ownerOnly(temporary)
        try {
            temporary.outputStream().use { output ->
                output.write(bytes)
                output.flush()
                output.fd.sync()
            }
            DurableFiles.replace(temporary, target)
            SecureFiles.ownerOnly(target)
        } finally {
            temporary.delete()
        }
    }

    // All four filenames come from DirectoryBundler, which excludes them from keystore sync
    // bundles in both directions ([DirectoryBundler.syncExclusions]): the record is sealed under
    // this device's master key and the keypair is this device's own, so a peer's copy arriving
    // over any of them would silently break this device's portable recovery. Building the names
    // from the exclusion constants is what keeps the writer and the filter from drifting apart.
    private fun directory(username: String) = File("${platform.getLocalPath()}/keystore/$username")
    private fun p12File(username: String) = File(directory(username), DirectoryBundler.portableRecoveryP12Name(username))
    private fun certificateFile(username: String) =
        File(directory(username), DirectoryBundler.portableRecoveryCertificateName(username))
    private fun materialFile(username: String) =
        File(directory(username), DirectoryBundler.PORTABLE_RECOVERY_RECORD_FILE_NAME)
    // This deliberately has no `.p12` extension, so it is never presented as a selectable keystore.
    private fun backupFile(username: String) =
        File(directory(username), DirectoryBundler.PORTABLE_RECOVERY_BACKUP_FILE_NAME)
    // The bytes retain the existing database filename so migration does not also relocate a live
    // database.  Settings exposes this exact absolute path; its contents become DER CMS.
    private fun vaultFile(username: String) =
        File("${platform.getLocalPath()}/database/${username.hashCode()}_encrypted_passman.database")

    private data class DecodedRecord(
        val password: String,
        val format: PortableVaultRecoveryFormat,
        val certificateFingerprint: ByteArray,
    )
    internal data class RecoveryKeyMaterial(
        val password: String,
        val format: PortableVaultRecoveryFormat,
        val privateKey: PrivateKey,
        val certificate: X509Certificate,
    )

    private fun ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private companion object {
        const val ALIAS = "passmanRecovery"
        const val RSA_BITS = 3072
        const val PIN_BYTES = 32
        const val LEGACY_RECORD_VERSION: Byte = 1
        const val BIP39_RECORD_VERSION: Byte = 2
    }
}
