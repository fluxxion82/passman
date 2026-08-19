package ai.passman.crypto

import java.security.SecureRandom
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

/**
 * Post-quantum **hybrid** KEM-DEM envelope. Confidentiality holds unless an attacker breaks
 * **both** X25519 and ML-KEM-768 — the two shared secrets are concatenated and run through one HKDF
 * (AND-construction), so a future quantum adversary who breaks X25519 still faces ML-KEM, and a flaw
 * in ML-KEM still leaves classical X25519.
 *
 * Per message: a fresh ephemeral X25519 key + a fresh ML-KEM encapsulation. The derived key binds the
 * whole transcript (suite/version, ephemeral X25519 public key, ML-KEM ciphertext, nonce, and the
 * recipient's own public keys) as HKDF info AND as the AES-256-GCM associated data, so any
 * substitution or downgrade fails authentication.
 *
 * Envelope v3 layout:
 * ```
 *   magic "PMNV"(4) | version(1)=1 | suite(1)=3 | ephX25519(32) | kemCtLen(2,BE) | kemCt | nonce(12) | ct+tag
 * ```
 *
 * Envelope v4 uses the same outer layout with `suite(1)=4`. Its GCM plaintext is:
 * ```
 *   sigLen(2,BE) | ML-DSA-65 signature | senderPubLen(2,BE) | sender ML-DSA-65 public key | payload
 * ```
 * The signature covers `header || SHA-256(sender public key) || payload`; the header is also GCM
 * associated data. v4 authenticates a payload to its embedded ML-DSA key. Binding that key to a
 * particular paired device is done by the caller passing the device's *stored* ML-DSA key as
 * [decrypt]'s `expectedSenderPublicKey`. When an expected key is supplied, an unsigned v3 envelope
 * is rejected outright: a caller who can name the sender's signing key must never accept a payload
 * that skipped the signature, or replacing a v4 envelope with a separately valid v3 one would strip
 * authentication (downgrade). v3 stays accepted only on the legacy path, where no sender key is
 * expected. This is the crypto primitive only — device key-management (how peers learn each other's
 * hybrid public keys, migration off RSA) is wired separately.
 */
object HybridKem {
    private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4E, 0x56) // "PMNV" — shared envelope magic
    private const val VERSION: Byte = 1
    private const val SUITE_HYBRID: Byte = 3
    private const val SUITE_SIGNED_HYBRID: Byte = 4

    private const val X25519_LEN = 32
    private const val GCM_NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val DEK_BYTES = 32
    private const val HEADER_FIXED = 4 + 1 + 1 + X25519_LEN + 2 // magic|ver|suite|ephPub|kemCtLen

    // Domain-separation label for the HKDF so these keys can never collide with another use.
    private val HKDF_SALT = "passman-hybrid-v3".encodeToByteArray()

    private val mlkemParams = MLKEMParameters.ml_kem_768
    private val secureRandom = SecureRandom()

    class KeyPair(val publicKey: HybridPublicKey, val privateKey: HybridPrivateKey)
    class HybridPublicKey(val x25519: ByteArray, val mlkem: ByteArray)
    class HybridPrivateKey(val x25519: ByteArray, val mlkem: ByteArray)

    fun generateKeyPair(): KeyPair {
        val xPriv = X25519PrivateKeyParameters(secureRandom)
        val xPub = xPriv.generatePublicKey()

        val kpg = MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(secureRandom, mlkemParams))
        }
        val kp = kpg.generateKeyPair()
        val mlPub = kp.public as MLKEMPublicKeyParameters
        val mlPriv = kp.private as MLKEMPrivateKeyParameters

        return KeyPair(
            HybridPublicKey(xPub.encoded, mlPub.encoded),
            HybridPrivateKey(xPriv.encoded, mlPriv.encoded),
        )
    }

    /** Reconstruct the public key from a stored private key (so only the private half need be persisted). */
    fun publicKeyOf(priv: HybridPrivateKey): HybridPublicKey {
        val x = X25519PrivateKeyParameters(priv.x25519, 0).generatePublicKey().encoded
        val m = MLKEMPrivateKeyParameters(mlkemParams, priv.mlkem).publicKeyParameters.encoded
        return HybridPublicKey(x, m)
    }

    fun encrypt(plain: ByteArray, recipient: HybridPublicKey, signer: MlDsa.KeyPair? = null): ByteArray {
        // Ephemeral X25519 + classical shared secret.
        val ephPriv = X25519PrivateKeyParameters(secureRandom)
        val ephPub = ephPriv.generatePublicKey().encoded
        val ss1 = x25519Agree(ephPriv, X25519PublicKeyParameters(recipient.x25519, 0))
        var ss2: ByteArray? = null
        var dek: ByteArray? = null
        try {
            // ML-KEM encapsulation to the recipient's PQ public key.
            val encapsulated = MLKEMGenerator(secureRandom)
                .generateEncapsulated(MLKEMPublicKeyParameters(mlkemParams, recipient.mlkem))
            val kemCt = encapsulated.encapsulation
            ss2 = encapsulated.secret

            val nonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }
            val suite = if (signer == null) SUITE_HYBRID else SUITE_SIGNED_HYBRID
            val header = buildHeader(suite, ephPub, kemCt)
            dek = deriveKey(ss1, ss2, header, recipient)
            val toEncrypt = signer?.let { signedPlaintext(header, plain, it) } ?: plain

            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(header)
            }
            try {
                val ct = cipher.doFinal(toEncrypt)
                return header + nonce + ct
            } finally {
                if (toEncrypt !== plain) toEncrypt.fill(0)
            }
        } finally {
            wipe(ss1, ss2, dek)
        }
    }

    fun decrypt(
        envelope: ByteArray,
        recipient: HybridPrivateKey,
        expectedSenderPublicKey: ByteArray? = null,
    ): ByteArray {
        require(envelope.size > HEADER_FIXED) { "truncated envelope" }
        require(envelope[0] == MAGIC[0] && envelope[1] == MAGIC[1] && envelope[2] == MAGIC[2] && envelope[3] == MAGIC[3]) {
            "bad magic"
        }
        require(envelope[4] == VERSION) { "unsupported version: ${envelope[4]}" }
        val suite = envelope[5]
        require(suite == SUITE_HYBRID || suite == SUITE_SIGNED_HYBRID) { "unsupported suite: $suite" }
        // An expected sender key means the caller requires authentication. Accepting an unsigned v3
        // here would let any envelope skip signature verification simply by omitting the signature —
        // the exact downgrade the expected key exists to prevent — so it is rejected before any
        // key agreement or decryption runs.
        if (expectedSenderPublicKey != null) {
            require(suite == SUITE_SIGNED_HYBRID) { "signed hybrid (v4) envelope required when a sender key is expected" }
        }

        val ephPub = envelope.copyOfRange(6, 6 + X25519_LEN)
        val kemCtLen = ((envelope[6 + X25519_LEN].toInt() and 0xFF) shl 8) or (envelope[7 + X25519_LEN].toInt() and 0xFF)
        val kemStart = HEADER_FIXED
        val nonceStart = kemStart + kemCtLen
        val ctStart = nonceStart + GCM_NONCE_BYTES
        require(envelope.size >= ctStart) { "truncated envelope" }

        val kemCt = envelope.copyOfRange(kemStart, nonceStart)
        val nonce = envelope.copyOfRange(nonceStart, ctStart)
        val header = envelope.copyOfRange(0, nonceStart) // magic..kemCt (matches encrypt's AAD)
        val ct = envelope.copyOfRange(ctStart, envelope.size)

        val xPriv = X25519PrivateKeyParameters(recipient.x25519, 0)
        val ss1 = x25519Agree(xPriv, X25519PublicKeyParameters(ephPub, 0))
        var ss2: ByteArray? = null
        var dek: ByteArray? = null
        try {
            ss2 = MLKEMExtractor(MLKEMPrivateKeyParameters(mlkemParams, recipient.mlkem)).extractSecret(kemCt)

            val recipientPub = HybridPublicKey(
                x25519 = xPriv.generatePublicKey().encoded,
                mlkem = MLKEMPrivateKeyParameters(mlkemParams, recipient.mlkem).publicKeyParameters.encoded,
            )
            dek = deriveKey(ss1, ss2, header, recipientPub)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(header)
            }
            val plain = cipher.doFinal(ct) // AEADBadTagException on tamper / wrong key / downgrade
            return if (suite == SUITE_SIGNED_HYBRID) {
                verifySignedPlaintext(header, plain, expectedSenderPublicKey)
            } else {
                plain
            }
        } finally {
            wipe(ss1, ss2, dek)
        }
    }

    private fun buildHeader(suite: Byte, ephPub: ByteArray, kemCt: ByteArray): ByteArray {
        require(ephPub.size == X25519_LEN)
        require(kemCt.size in 1..0xFFFF)
        val header = ByteArray(HEADER_FIXED + kemCt.size)
        var i = 0
        MAGIC.copyInto(header, i); i += 4
        header[i++] = VERSION
        header[i++] = suite
        ephPub.copyInto(header, i); i += X25519_LEN
        header[i++] = ((kemCt.size ushr 8) and 0xFF).toByte()
        header[i++] = (kemCt.size and 0xFF).toByte()
        kemCt.copyInto(header, i)
        return header
    }

    /** HKDF-SHA256 over (ss1 || ss2), binding the transcript + recipient public keys as info. */
    private fun deriveKey(ss1: ByteArray, ss2: ByteArray, header: ByteArray, recipient: HybridPublicKey): ByteArray {
        val ikm = ss1 + ss2
        try {
            val info = header + recipient.x25519 + recipient.mlkem
            val hkdf = HKDFBytesGenerator(SHA256Digest()).apply { init(HKDFParameters(ikm, HKDF_SALT, info)) }
            return ByteArray(DEK_BYTES).also { hkdf.generateBytes(it, 0, DEK_BYTES) }
        } finally {
            wipe(ikm)
        }
    }

    private fun signedPlaintext(header: ByteArray, payload: ByteArray, signer: MlDsa.KeyPair): ByteArray {
        require(signer.publicKey.size == MlDsa.PUBLIC_KEY_BYTES) { "bad ML-DSA-65 public key length" }
        require(signer.privateSeed.size == MlDsa.PRIVATE_SEED_BYTES) { "bad ML-DSA-65 private seed length" }
        val publicKeyHash = MessageDigest.getInstance("SHA-256").digest(signer.publicKey)
        val signingInput = header + publicKeyHash + payload
        try {
            val signature = MlDsa.sign(signingInput, signer.privateSeed)
            require(signature.size == MlDsa.SIGNATURE_BYTES) { "bad ML-DSA-65 signature length" }
            val out = ByteArray(2 + signature.size + 2 + signer.publicKey.size + payload.size)
            var i = 0
            out[i++] = ((signature.size ushr 8) and 0xFF).toByte()
            out[i++] = (signature.size and 0xFF).toByte()
            signature.copyInto(out, i); i += signature.size
            out[i++] = ((signer.publicKey.size ushr 8) and 0xFF).toByte()
            out[i++] = (signer.publicKey.size and 0xFF).toByte()
            signer.publicKey.copyInto(out, i); i += signer.publicKey.size
            payload.copyInto(out, i)
            return out
        } finally {
            signingInput.fill(0)
            publicKeyHash.fill(0)
        }
    }

    private fun verifySignedPlaintext(
        header: ByteArray,
        signedPlaintext: ByteArray,
        expectedSenderPublicKey: ByteArray?,
    ): ByteArray {
        try {
            require(signedPlaintext.size >= 2 + MlDsa.SIGNATURE_BYTES + 2 + MlDsa.PUBLIC_KEY_BYTES) {
                "truncated signed envelope"
            }
            val signatureLength = unsignedShort(signedPlaintext, 0)
            require(signatureLength == MlDsa.SIGNATURE_BYTES) { "bad ML-DSA-65 signature length" }
            val publicKeyLengthOffset = 2 + signatureLength
            val publicKeyLength = unsignedShort(signedPlaintext, publicKeyLengthOffset)
            require(publicKeyLength == MlDsa.PUBLIC_KEY_BYTES) { "bad ML-DSA-65 public key length" }
            val publicKeyOffset = publicKeyLengthOffset + 2
            require(signedPlaintext.size >= publicKeyOffset + publicKeyLength) { "truncated signed envelope" }
            val signature = signedPlaintext.copyOfRange(2, publicKeyLengthOffset)
            val publicKey = signedPlaintext.copyOfRange(publicKeyOffset, publicKeyOffset + publicKeyLength)
            val payload = signedPlaintext.copyOfRange(publicKeyOffset + publicKeyLength, signedPlaintext.size)
            if (expectedSenderPublicKey != null) {
                require(expectedSenderPublicKey.size == MlDsa.PUBLIC_KEY_BYTES) { "bad expected ML-DSA-65 public key length" }
                require(MessageDigest.isEqual(publicKey, expectedSenderPublicKey)) { "unexpected ML-DSA-65 sender key" }
            }
            val publicKeyHash = MessageDigest.getInstance("SHA-256").digest(publicKey)
            val signingInput = header + publicKeyHash + payload
            try {
                require(MlDsa.verify(signingInput, signature, publicKey)) { "invalid ML-DSA-65 envelope signature" }
                return payload
            } finally {
                signingInput.fill(0)
                publicKeyHash.fill(0)
            }
        } finally {
            signedPlaintext.fill(0)
        }
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    /**
     * Best-effort zeroization of intermediate secrets. The JVM still copies key bytes internally
     * (e.g. inside [SecretKeySpec] and the cipher), so this shrinks the exposure window rather than
     * eliminating it — the strongest guarantee available without native memory management.
     */
    private fun wipe(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }

    private fun x25519Agree(priv: X25519PrivateKeyParameters, pub: X25519PublicKeyParameters): ByteArray {
        val out = ByteArray(X25519_LEN)
        X25519Agreement().apply { init(priv) }.calculateAgreement(pub, out, 0)
        // Reject a contributory/low-order all-zero shared secret.
        if (out.all { it == 0.toByte() }) throw IllegalStateException("degenerate X25519 shared secret")
        return out
    }
}
