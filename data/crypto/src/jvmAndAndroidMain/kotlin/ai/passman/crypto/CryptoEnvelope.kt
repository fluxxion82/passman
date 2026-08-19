package ai.passman.crypto

import ai.passman.crypto.model.EncryptedData
import java.security.Key
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json

/**
 * Self-describing, versioned encryption envelope for vault-at-rest and LAN-wire payloads.
 *
 * Wire/at-rest layout (suite v2):
 * ```
 *   magic(4)="PMNV" | version(1)=1 | suite(1)=2 | wrappedKeyLen(2,BE) | wrappedKey | nonce(12) | ct+tag
 * ```
 * The whole header (everything before the ciphertext, including the RSA-wrapped DEK and the GCM
 * nonce) is bound as the AEAD associated data, so a suite/version downgrade or a wrapped-key/nonce
 * substitution fails authentication. Suite v2 = RSA-OAEP(SHA-256) key wrap + AES-256-GCM, with a
 * fresh random DEK and nonce per call.
 *
 * [decrypt] auto-detects the format: bytes starting with [MAGIC] are the binary v2 envelope; anything
 * else is treated as a **legacy v1** blob (JSON [EncryptedData]: RSA-PKCS1 wrap + AES-CBC fixed-IV,
 * unauthenticated). v1 is read-only for backward compatibility with data written before this change;
 * everything is re-written as v2 on the next write.
 */
object CryptoEnvelope {
    private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4E, 0x56) // "PMNV"
    private const val VERSION: Byte = 1
    private const val SUITE_OAEP_GCM: Byte = 2

    private const val AES_KEY_BITS = 256
    private const val GCM_NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_FIXED_BYTES = 4 + 1 + 1 + 2 // magic + version + suite + wrappedKeyLen

    private val secureRandom = SecureRandom()

    fun encrypt(plain: ByteArray, publicKey: Key): ByteArray {
        val dek = KeyGenerator.getInstance("AES").apply { init(AES_KEY_BITS, secureRandom) }.generateKey()
        val wrappedKey = wrapKeyRsaOaep(dek, publicKey)
        val nonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }

        val header = buildHeader(wrappedKey, nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, dek, GCMParameterSpec(GCM_TAG_BITS, nonce))
            updateAAD(header) // bind the whole header (suite, wrapped key, nonce) to the tag
        }
        val ciphertext = cipher.doFinal(plain)
        return header + ciphertext
    }

    fun decrypt(envelope: ByteArray, privateKey: Key): ByteArray =
        if (looksLikeV2(envelope)) decryptV2(envelope, privateKey) else decryptLegacyV1(envelope, privateKey)

    private fun looksLikeV2(bytes: ByteArray): Boolean =
        bytes.size > HEADER_FIXED_BYTES &&
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3]

    private fun buildHeader(wrappedKey: ByteArray, nonce: ByteArray): ByteArray {
        require(wrappedKey.size in 1..0xFFFF) { "wrapped key length out of range: ${wrappedKey.size}" }
        val header = ByteArray(HEADER_FIXED_BYTES + wrappedKey.size + nonce.size)
        var i = 0
        MAGIC.copyInto(header, i); i += MAGIC.size
        header[i++] = VERSION
        header[i++] = SUITE_OAEP_GCM
        header[i++] = ((wrappedKey.size ushr 8) and 0xFF).toByte()
        header[i++] = (wrappedKey.size and 0xFF).toByte()
        wrappedKey.copyInto(header, i); i += wrappedKey.size
        nonce.copyInto(header, i)
        return header
    }

    private fun decryptV2(envelope: ByteArray, privateKey: Key): ByteArray {
        require(envelope[4] == VERSION) { "unsupported envelope version: ${envelope[4]}" }
        require(envelope[5] == SUITE_OAEP_GCM) { "unsupported crypto suite: ${envelope[5]}" }
        val wrappedKeyLen = ((envelope[6].toInt() and 0xFF) shl 8) or (envelope[7].toInt() and 0xFF)
        val keyStart = HEADER_FIXED_BYTES
        val nonceStart = keyStart + wrappedKeyLen
        val ctStart = nonceStart + GCM_NONCE_BYTES
        require(envelope.size >= ctStart) { "truncated envelope" }

        val wrappedKey = envelope.copyOfRange(keyStart, nonceStart)
        val nonce = envelope.copyOfRange(nonceStart, ctStart)
        val header = envelope.copyOfRange(0, ctStart)
        val ciphertext = envelope.copyOfRange(ctStart, envelope.size)

        val dek = unwrapKeyRsaOaep(wrappedKey, privateKey)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, dek, GCMParameterSpec(GCM_TAG_BITS, nonce))
            updateAAD(header)
        }
        return cipher.doFinal(ciphertext) // throws AEADBadTagException on tamper / wrong key
    }

    private fun wrapKeyRsaOaep(dek: Key, publicKey: Key): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        // Pin MGF1 to SHA-256 explicitly: several providers default MGF1 to SHA-1 even with an
        // SHA-256 OAEP digest, which then fails to interop. Be unambiguous on both ends.
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams())
        val raw = dek.encoded // getEncoded() returns a fresh copy — wipe it once wrapped
        try {
            return cipher.doFinal(raw)
        } finally {
            raw.fill(0)
        }
    }

    private fun unwrapKeyRsaOaep(wrappedKey: ByteArray, privateKey: Key): Key {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams())
        val raw = cipher.doFinal(wrappedKey)
        // SecretKeySpec clones the array, so the local copy can be wiped immediately. Best-effort:
        // the clone inside the key object (and cipher internals) still lives until GC.
        return SecretKeySpec(raw, "AES").also { raw.fill(0) }
    }

    private fun oaepParams() =
        OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)

    // ---- Legacy v1 (read-only; unauthenticated AES-CBC fixed-IV + RSA-PKCS1) ----

    private fun decryptLegacyV1(envelope: ByteArray, privateKey: Key): ByteArray {
        val data = Json.decodeFromString<EncryptedData>(String(envelope))
        val unwrapCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
            init(Cipher.DECRYPT_MODE, privateKey)
        }
        val aesKey = unwrapCipher.doFinal(data.encryptedKey).let { raw ->
            SecretKeySpec(raw, 0, raw.size, "AES").also { raw.fill(0) }
        }
        val cbc = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
            init(Cipher.DECRYPT_MODE, aesKey, IvParameterSpec(data.iv))
        }
        return cbc.doFinal(data.encryptedMessage)
    }

    /**
     * Produces a legacy v1 blob. Retained ONLY so tests can prove the v1 reader still decrypts data
     * written by the pre-envelope code. Production never writes v1.
     */
    internal fun encryptLegacyV1ForTest(plain: ByteArray, publicKey: Key): ByteArray {
        val aesKey = KeyGenerator.getInstance("AES").apply { init(AES_KEY_BITS) }.generateKey()
        val iv = ByteArray(16) { 0 }
        val cbc = Cipher.getInstance("AES/CBC/PKCS5Padding").apply {
            init(Cipher.ENCRYPT_MODE, aesKey, IvParameterSpec(iv))
        }
        val ct = cbc.doFinal(plain)
        val wrap = Cipher.getInstance("RSA/ECB/PKCS1Padding").apply {
            init(Cipher.ENCRYPT_MODE, publicKey)
        }.doFinal(aesKey.encoded)
        return Json.encodeToString(EncryptedData(encryptedMessage = ct, encryptedKey = wrap, iv = iv)).toByteArray()
    }
}
