package ai.passman.crypto.keyring

import ai.passman.crypto.vault.VaultFailure
import ai.passman.crypto.vault.VaultSessionKey
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Which device-local private key file an envelope carries.
 *
 * The purpose selects the [KeyringSubkeys] label *and* is written into the header, so a `hybrid.key`
 * moved over `mldsa.key` is rejected by name before the tag check rather than only by the tag. The two
 * subkeys already differ, so the tag would fail anyway; the byte turns "authentication failed" into
 * "this is the wrong file", which is the difference between quarantining a file and hunting a
 * corruption that never happened.
 */
enum class KeyFilePurpose(internal val id: Byte) {
    HYBRID(1),
    ML_DSA(2),
    RECOVERY_PASSWORD(3),
}

/**
 * The at-rest envelope for this device's post-quantum private key files, `hybrid.key` and
 * `mldsa.key`.
 *
 * ```
 *   magic "PMKF"(4) | version(1)=1 | purpose(1) | nonce(12) | ciphertext+tag
 * ```
 *
 * The whole 18-byte header — magic, version, purpose and nonce — is bound as AES-256-GCM associated
 * data, following the same "everything before this ciphertext" idiom as [KeyringEnvelope] and
 * `CryptoEnvelope`.
 *
 * ## Why this exists rather than reusing the vault or the RSA envelope
 *
 * These two files hold the device's *pairing identity*. Losing either one is not like losing a cache:
 * every peer that already holds the matching public key is orphaned and has to be paired again by
 * hand. So the key that protects them must depend on as little as possible.
 *
 * - Not the RSA identity (`CryptoEnvelope`, what these files used before): the `.pfx` is a separate
 *   artifact with its own loss and restore story, and the whole plan is to stop RSA being load
 *   bearing at rest.
 * - Not the vault root: that root lives *inside* the vault envelope, so restoring or losing the vault
 *   database would change it and make both private keys undecryptable — permanently breaking every
 *   pairing, recoverable only by re-pairing every peer.
 *
 * What is left is the Device Master Key, which lives in its own small file, does not rotate on a
 * password change, and is exactly what [KeyringSubkeys] derives from. Deleting the vault database
 * therefore costs the user their passwords (restorable from a backup) and not their device identity.
 *
 * ## Why it lives in `data:crypto`
 *
 * The key managers that call it are in `data:repo`, but [VaultSessionKey.material] is deliberately
 * `internal` to this module — the unwrapped master key is not supposed to be reachable from anywhere
 * else, which is the same reason `VaultCipher.identityStorePassword` exists as a boundary method
 * rather than as a `KeyringSubkeys` call at its call site. Putting the seal/open pair here keeps the
 * master key inside the module that owns it and hands `data:repo` nothing but ciphertext.
 *
 * Wiping is best-effort in exactly the sense [KeyringEnvelope] documents: the derived subkey is zeroed
 * on every path, but `SecretKeySpec` clones what it is handed into an array it never wipes.
 */
object KeyFileEnvelope {

    private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4B, 0x46) // "PMKF"
    private const val VERSION: Byte = 1

    internal const val VERSION_OFFSET = 4
    internal const val PURPOSE_OFFSET = 5
    internal const val NONCE_OFFSET = 6

    internal const val GCM_NONCE_BYTES = 12
    private const val GCM_TAG_BYTES = 16
    private const val GCM_TAG_BITS = 128

    /** Everything the AEAD binds as associated data. */
    internal const val HEADER_BYTES = NONCE_OFFSET + GCM_NONCE_BYTES

    /** An envelope over an empty plaintext is still a full header plus a tag. */
    internal const val MIN_FILE_BYTES = HEADER_BYTES + GCM_TAG_BYTES

    private val secureRandom = SecureRandom()

    /**
     * True when [bytes] carries this envelope's magic.
     *
     * This is the migration discriminator: anything that is *not* one of these is a legacy
     * RSA-wrapped key file written before the keyring existed, and has to be read through
     * `CryptoService` once and rewritten here. The two magics differ ("PMKF" against `CryptoEnvelope`'s
     * "PMNV"), and a legacy v1 blob is JSON with no magic at all, so the three formats cannot be
     * confused for one another.
     */
    fun isKeyFileEnvelope(bytes: ByteArray): Boolean =
        bytes.size > PURPOSE_OFFSET &&
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3]

    /** Seal [plaintext] under the [purpose]'s keyring subkey with a fresh nonce. */
    fun seal(plaintext: ByteArray, purpose: KeyFilePurpose, sessionKey: VaultSessionKey): ByteArray {
        var key: ByteArray? = null
        try {
            key = subkey(purpose, sessionKey)
            val nonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }
            val header = ByteArray(HEADER_BYTES)
            MAGIC.copyInto(header, 0)
            header[VERSION_OFFSET] = VERSION
            header[PURPOSE_OFFSET] = purpose.id
            nonce.copyInto(header, NONCE_OFFSET)
            return header + gcm(Cipher.ENCRYPT_MODE, key, nonce, header, plaintext)
        } finally {
            key?.fill(0)
        }
    }

    /**
     * Open an envelope written by [seal].
     *
     * @throws VaultFailure.Malformed if [bytes] is not a readable envelope of this [purpose] at all.
     *   Nothing was decrypted, so the caller learns nothing about whether the content is intact.
     * @throws VaultFailure.Tampered if the structure is right but the tag does not verify: the file
     *   was damaged, or the session key belongs to a different device master key. A GCM tag cannot say
     *   which — see [VaultFailure.Tampered].
     */
    fun open(bytes: ByteArray, purpose: KeyFilePurpose, sessionKey: VaultSessionKey): ByteArray {
        // Structure first, in full, before a key is derived: every slice below is inside a length that
        // has already been checked, so a truncated file is a typed failure and not an index exception.
        if (!isKeyFileEnvelope(bytes)) throw VaultFailure.Malformed("not a key file envelope")
        if (bytes[VERSION_OFFSET] != VERSION) {
            throw VaultFailure.Malformed("unsupported key file version: ${bytes[VERSION_OFFSET]}")
        }
        if (bytes[PURPOSE_OFFSET] != purpose.id) {
            throw VaultFailure.Malformed(
                "key file purpose mismatch: expected ${purpose.id}, found ${bytes[PURPOSE_OFFSET]}",
            )
        }
        if (bytes.size < MIN_FILE_BYTES) {
            throw VaultFailure.Malformed("truncated key file: ${bytes.size} bytes, minimum $MIN_FILE_BYTES")
        }

        var key: ByteArray? = null
        try {
            key = subkey(purpose, sessionKey)
            return try {
                gcm(
                    mode = Cipher.DECRYPT_MODE,
                    key = key,
                    nonce = bytes.copyOfRange(NONCE_OFFSET, HEADER_BYTES),
                    aad = bytes.copyOfRange(0, HEADER_BYTES),
                    input = bytes.copyOfRange(HEADER_BYTES, bytes.size),
                )
            } catch (e: GeneralSecurityException) {
                throw VaultFailure.Tampered("the $purpose key file failed authentication", e)
            }
        } finally {
            key?.fill(0)
        }
    }

    /**
     * Exhaustive on purpose: adding a [KeyFilePurpose] without giving it a label is a compile error
     * here rather than a file sealed under whichever key the fallthrough happened to pick.
     */
    private fun subkey(purpose: KeyFilePurpose, sessionKey: VaultSessionKey): ByteArray {
        val dmk = sessionKey.material()
        return when (purpose) {
            KeyFilePurpose.HYBRID -> KeyringSubkeys.hybridKeyFileKey(dmk)
            KeyFilePurpose.ML_DSA -> KeyringSubkeys.mlDsaKeyFileKey(dmk)
            KeyFilePurpose.RECOVERY_PASSWORD -> KeyringSubkeys.recoveryPasswordKey(dmk)
        }
    }

    private fun gcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        updateAAD(aad)
    }.doFinal(input)
}
