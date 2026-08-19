package ai.passman.crypto

import java.security.Key

/**
 * Single entry point for the versioned envelope family. Encryption picks the suite; decryption
 * dispatches on the envelope's own suite byte, so a receiver transparently handles legacy v1, the
 * classical v2 (RSA-OAEP + AES-GCM), post-quantum v3 (hybrid X25519+ML-KEM), and signed v4
 * (hybrid X25519+ML-KEM + ML-DSA-65) formats.
 *
 * The hybrid public key is exchanged on the wire as `x25519(32) | mlkemLen(2,BE) | mlkem`.
 */
object EnvelopeCodec {
    private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4E, 0x56) // "PMNV"
    private const val SUITE_OFFSET = 5
    private const val SUITE_HYBRID: Byte = 3
    private const val SUITE_SIGNED_HYBRID: Byte = 4
    private const val X25519_LEN = 32

    /** Post-quantum encryption to a peer's hybrid public key (v3 without [signer], v4 with it). */
    fun encryptHybrid(
        plain: ByteArray,
        recipient: HybridKem.HybridPublicKey,
        signer: MlDsa.KeyPair? = null,
    ): ByteArray = HybridKem.encrypt(plain, recipient, signer)

    /** Classical encryption to an RSA public key (suite v2). */
    fun encryptClassical(plain: ByteArray, rsaPublicKey: Key): ByteArray =
        CryptoEnvelope.encrypt(plain, rsaPublicKey)

    /**
     * Decrypt any supported envelope. [rsaPrivate] handles legacy v1 + classical v2; [hybridPrivate]
     * (may be null when the device has no hybrid key yet) handles post-quantum v3. Throws if a v3
     * envelope arrives without a hybrid private key. v4 verifies its embedded ML-DSA sender key.
     */
    fun decrypt(bytes: ByteArray, rsaPrivate: Key, hybridPrivate: HybridKem.HybridPrivateKey?): ByteArray =
        if (isHybrid(bytes)) {
            val priv = hybridPrivate ?: throw IllegalStateException("hybrid (v3) envelope but no hybrid private key")
            HybridKem.decrypt(bytes, priv)
        } else {
            CryptoEnvelope.decrypt(bytes, rsaPrivate)
        }

    /**
     * Decrypt a v3/v4 hybrid envelope, including v4 ML-DSA sender-signature verification. A non-null
     * [expectedSenderPublicKey] makes this strict: unsigned v3 is rejected as a downgrade, and a v4
     * envelope must be signed by exactly that key.
     */
    fun decrypt(
        bytes: ByteArray,
        hybridPrivate: HybridKem.HybridPrivateKey,
        expectedSenderPublicKey: ByteArray? = null,
    ): ByteArray {
        require(isHybrid(bytes)) { "not a hybrid envelope" }
        return HybridKem.decrypt(bytes, hybridPrivate, expectedSenderPublicKey)
    }

    /**
     * Strict decryption for peers whose pairing requires signed hybrid sync ([expectedSenderPublicKey]
     * is the peer's ML-DSA key persisted at pairing, and it is deliberately non-nullable). The
     * envelope must be suite 4 and its embedded sender key must equal the expected one; suite 3 —
     * even one that would otherwise decrypt cleanly — is rejected before any decryption, because an
     * upgraded peer never sends unsigned payloads, so an unsigned envelope is a downgrade rather
     * than a compatibility case.
     */
    fun decryptSignedHybrid(
        bytes: ByteArray,
        hybridPrivate: HybridKem.HybridPrivateKey,
        expectedSenderPublicKey: ByteArray,
    ): ByteArray {
        require(isHybrid(bytes) && bytes[SUITE_OFFSET] == SUITE_SIGNED_HYBRID) {
            "signed hybrid (v4) envelope required"
        }
        return HybridKem.decrypt(bytes, hybridPrivate, expectedSenderPublicKey)
    }

    private fun isHybrid(bytes: ByteArray): Boolean =
        bytes.size > SUITE_OFFSET &&
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3] &&
            (bytes[SUITE_OFFSET] == SUITE_HYBRID || bytes[SUITE_OFFSET] == SUITE_SIGNED_HYBRID)

    fun serializePublicKey(pub: HybridKem.HybridPublicKey): ByteArray {
        require(pub.x25519.size == X25519_LEN) { "bad X25519 length" }
        require(pub.mlkem.size in 1..0xFFFF) { "bad ML-KEM length" }
        val out = ByteArray(X25519_LEN + 2 + pub.mlkem.size)
        pub.x25519.copyInto(out, 0)
        out[X25519_LEN] = ((pub.mlkem.size ushr 8) and 0xFF).toByte()
        out[X25519_LEN + 1] = (pub.mlkem.size and 0xFF).toByte()
        pub.mlkem.copyInto(out, X25519_LEN + 2)
        return out
    }

    fun deserializePublicKey(bytes: ByteArray): HybridKem.HybridPublicKey {
        require(bytes.size > X25519_LEN + 2) { "hybrid public key too short" }
        val mlkemLen = ((bytes[X25519_LEN].toInt() and 0xFF) shl 8) or (bytes[X25519_LEN + 1].toInt() and 0xFF)
        require(bytes.size == X25519_LEN + 2 + mlkemLen) { "hybrid public key length mismatch" }
        return HybridKem.HybridPublicKey(
            x25519 = bytes.copyOfRange(0, X25519_LEN),
            mlkem = bytes.copyOfRange(X25519_LEN + 2, bytes.size),
        )
    }
}
