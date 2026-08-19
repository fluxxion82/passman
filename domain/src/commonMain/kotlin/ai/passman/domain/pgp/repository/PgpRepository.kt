package ai.passman.domain.pgp.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.*

interface PgpRepository {
    suspend fun getKeys(): List<PgpKeyPair>
    suspend fun getKey(keyId: Long): PgpKeyPair?

    /**
     * Path of a file that actually contains the PUBLIC key ring for [keyId]. Unlike the path on
     * the listed [PgpKeyPair.publicKey] — which can point at the secret-ring file when no public
     * ring exists — this never resolves to a secret ring, so it is the only path safe to share.
     */
    suspend fun getPublicKeyPath(keyId: Long): Outcome<String>

    /**
     * Path of the standalone file holding [keyId]'s SECRET key ring, released only after
     * [passphrase] actually unlocked the secret key (a real private-key extraction, not a string
     * comparison). A wrong passphrase fails with `PgpFailure.WrongPassword`; a file that also
     * carries other keys or rings is refused — the whole file is what leaves the app.
     */
    suspend fun getSecretKeyPath(keyId: Long, passphrase: String): Outcome<String>
    suspend fun createPgpKey(
        name: String,
        email: String,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long,
    ): Outcome<String>
    suspend fun encryptPgpMessage(plainText: String, publicKeyPath: String): Outcome<String>
    suspend fun encryptPgpFile(filePath: String, publicKeyPath: String): Outcome<String>
    suspend fun decryptPgpMessage(encryptedText: String, secretKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun decryptPgpFile(encryptedFilePath: String, secretKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun clearSign(plainText: String, privateKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun clearSignFile(plainFilePath: String, privateKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun sign(plainText: String, privateKeyPath: String, passPhrase: String, armor: Boolean, digestName: String): Outcome<String>
    suspend fun verifyClearSignature(encryptedText: String, publicKeyPath: String): Outcome<Unit>
    suspend fun verifyClearSignatureFile(encryptedFilePath: String, publicKeyPath: String): Outcome<Unit>
    suspend fun verifySignature(signatureText: String, publicKeyPath: String): Outcome<Unit>
    suspend fun signAndEncrypt(plainText: String, publicKeyPath: String, privateKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun signAndEncryptFile(plainFilePath: String, publicKeyPath: String, privateKeyPath: String, keyPassword: String): Outcome<String>
    suspend fun verifyAndDecrypt(encryptedText: String, privateKeyPath: String, keyPassword: String, publicKeyPath: String): Outcome<String>
    suspend fun verifyAndDecryptFile(encryptedFilePath: String, privateKeyPath: String, keyPassword: String, publicKeyPath: String): Outcome<String>

    suspend fun modifyUserId(keyPair: PgpKeyPair, password: String, userId: UserId, userIdAction: UserIdAction): Outcome<Unit>

    suspend fun addSubKey(
        keyPair: PgpKeyPair,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long,
    ): Outcome<Unit>
    suspend fun modifySubKey(
        keyPair: PgpKeyPair,
        password: String,
        subKeyId: String,
        action: SubKeyAction,
    ): Outcome<Unit>

    suspend fun changeKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long)
    suspend fun changeSubKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long)
    suspend fun changeKeyPassword(keyPair: PgpKeyPair, oldPassword: String, newPassword: String): Outcome<Unit>
    suspend fun importPgpFile(path: String): Outcome<Unit>

    /**
     * Installs the developer public key bundled with the app into the account's key directory,
     * after verifying the bundled armor still parses to exactly the pinned developer fingerprint
     * (a mismatch is refused and nothing is written or recorded). A file already at the
     * destination is only ever replaced when it itself holds the developer key; any other
     * occupant (e.g. placed there by sync) is refused, never overwritten.
     *
     * Success value: `true` when the key was (re)imported, `false` for the already-imported
     * skip. [force] is the explicit menu action: it re-imports even when the once-per-account
     * flag is set (still verified, still occupant-guarded).
     *
     * Scope of "deletion is final": PER DEVICE. The flag is device-local while the key file
     * syncs between paired devices — delete the key on device A, log in on device B, and B's
     * auto-import re-installs it and sync can carry it back to A. Deliberate: no tombstone
     * machinery for a public convenience key.
     */
    suspend fun importBundledDeveloperKey(force: Boolean): Outcome<Boolean>

    suspend fun deletePgpKey(keyId: Long): Outcome<Unit>

    /**
     * Creates the account's default PGP key rings — the same fixed-name secret/public ring pair
     * the signup path creates — sealed with [passphrase]. Refuses (without touching anything)
     * when either default ring file already exists, so it can never overwrite key material that
     * arrived by sync or import. Used by [ai.passman.domain.pgp.EnsureDefaultPgpRings] to
     * re-provision an account whose signup-time rings had to be rolled back.
     */
    suspend fun createDefaultKeyRings(passphrase: String): Outcome<Unit>

    /**
     * Deletes ONLY the two fixed-name default ring files; every other key file in the account's
     * pgp directory is untouched. This is rollback plumbing for freshly created default rings
     * whose passphrase could not be recorded in the vault — a ring nobody holds the passphrase
     * for is unrecoverable and worse than absent.
     */
    suspend fun deleteDefaultKeyRings(): Outcome<Unit>

    suspend fun transferPgpKeys(hostName: String): Outcome<Unit>
    suspend fun pushPgpKeys(hostName: String): Outcome<Unit>
    suspend fun pullPgpKeys(hostName: String): Outcome<Unit>
}
