package ai.passman.crypto.keyring

import java.util.Base64
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * Domain-separated subkeys derived from the Device Master Key held in [KeyringEnvelope].
 *
 * HKDF-SHA256 with `ikm = DMK`, a fixed salt, and one label per purpose. The labels are the whole
 * point: they guarantee that the key wrapping the vault can never equal the key encrypting
 * `mldsa.key`, so compromising one artifact does not compromise another, and a future purpose can be
 * added without touching anything already on disk.
 *
 * There is deliberately **no** `derive(dmk, label: String)` overload. A caller that mistypes a label
 * gets a perfectly valid but unrelated 32 bytes with no error anywhere — data written under it would
 * be unrecoverable. One named function per label makes that a compile error instead.
 */
object KeyringSubkeys {

    private val HKDF_SALT = "passman-keyring-v1".encodeToByteArray()

    private val VAULT_WRAP_LABEL = "passman/vault-wrap/v1".encodeToByteArray()
    private val HYBRID_KEY_FILE_LABEL = "passman/keyfile/hybrid/v1".encodeToByteArray()
    private val ML_DSA_KEY_FILE_LABEL = "passman/keyfile/mldsa/v1".encodeToByteArray()
    private val RECOVERY_PASSWORD_LABEL = "passman/keyfile/recovery-password/v1".encodeToByteArray()
    private val PKCS12_PASSWORD_LABEL = "passman/pkcs12-password/v1".encodeToByteArray()

    internal const val SUBKEY_BYTES = 32

    /** Wraps the random vault root key inside the suite-v5 vault envelope. */
    fun vaultWrapKey(dmk: ByteArray): ByteArray = derive(dmk, VAULT_WRAP_LABEL)

    /** Encrypts the stored hybrid (X25519 + ML-KEM-768) private key file. */
    fun hybridKeyFileKey(dmk: ByteArray): ByteArray = derive(dmk, HYBRID_KEY_FILE_LABEL)

    /** Encrypts the stored ML-DSA-65 private key file. */
    fun mlDsaKeyFileKey(dmk: ByteArray): ByteArray = derive(dmk, ML_DSA_KEY_FILE_LABEL)

    /** Encrypts the generated password and certificate pin for the portable recovery P12. */
    fun recoveryPasswordKey(dmk: ByteArray): ByteArray = derive(dmk, RECOVERY_PASSWORD_LABEL)

    /**
     * The PKCS#12 store and key password: 256 bits of derived material, Base64 without padding.
     *
     * BouncyCastle's PKCS#12 PBE is SHA-1-based and not memory-hard, so it must never protect
     * anything guessable. Deriving the password from the DMK puts the store behind the same single
     * Argon2id derivation as everything else instead of behind a second, far cheaper KDF over the
     * same login password.
     *
     * The raw 32 bytes are wiped as soon as they are encoded, but the returned `String` is immutable
     * and **cannot** be wiped — it survives until the GC collects it, and `KeyStore.load` wants a
     * `CharArray` it will copy anyway. Hold it for as short a time as possible; do not cache it.
     */
    fun pkcs12Password(dmk: ByteArray): String {
        val raw = derive(dmk, PKCS12_PASSWORD_LABEL)
        try {
            return Base64.getEncoder().withoutPadding().encodeToString(raw)
        } finally {
            raw.fill(0)
        }
    }

    private fun derive(dmk: ByteArray, label: ByteArray): ByteArray {
        require(dmk.size == KeyringEnvelope.DMK_BYTES) {
            "device master key must be ${KeyringEnvelope.DMK_BYTES} bytes, was ${dmk.size}"
        }
        val hkdf = HKDFBytesGenerator(SHA256Digest()).apply {
            init(HKDFParameters(dmk, HKDF_SALT, label))
        }
        return ByteArray(SUBKEY_BYTES).also { hkdf.generateBytes(it, 0, SUBKEY_BYTES) }
    }
}
