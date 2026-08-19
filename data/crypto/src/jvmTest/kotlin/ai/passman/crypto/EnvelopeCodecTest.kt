package ai.passman.crypto

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

class EnvelopeCodecTest {
    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val hybrid = HybridKem.generateKeyPair()

    @Test
    fun dispatchesClassicalV2ByteRoundTrip() {
        val plain = "classical".encodeToByteArray()
        val env = EnvelopeCodec.encryptClassical(plain, rsa.public)
        val out = EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = hybrid.privateKey)
        assertContentEquals(plain, out)
    }

    @Test
    fun dispatchesHybridV3ByteRoundTrip() {
        val plain = "post-quantum".encodeToByteArray()
        val env = EnvelopeCodec.encryptHybrid(plain, hybrid.publicKey)
        val out = EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = hybrid.privateKey)
        assertContentEquals(plain, out)
    }

    @Test
    fun dispatchesSignedHybridV4ByteRoundTrip() {
        val plain = "authenticated post-quantum".encodeToByteArray()
        val signer = MlDsa.generateKeyPair()

        val env = EnvelopeCodec.encryptHybrid(plain, hybrid.publicKey, signer)

        assertEquals(4, env[5], "suite = signed hybrid")
        assertContentEquals(plain, EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = hybrid.privateKey))
    }

    @Test
    fun signedHybridV4RejectsTamperedPayload() {
        val env = EnvelopeCodec.encryptHybrid(
            "authenticated post-quantum".encodeToByteArray(),
            hybrid.publicKey,
            MlDsa.generateKeyPair(),
        )

        env[env.lastIndex] = (env.last().toInt() xor 0x01).toByte()

        assertFailsWith<AEADBadTagException> { EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = hybrid.privateKey) }
    }

    @Test
    fun signedHybridV4RejectsTamperedEmbeddedPublicKey() {
        val env = EnvelopeCodec.encryptHybrid(
            "authenticated post-quantum".encodeToByteArray(),
            hybrid.publicKey,
            MlDsa.generateKeyPair(),
        )
        val headerLen = 4 + 1 + 1 + 32 + 2 + 1_088
        val embeddedPublicKeyCipherOffset = headerLen + 12 + 2 + 3_309 + 2
        env[embeddedPublicKeyCipherOffset] = (env[embeddedPublicKeyCipherOffset].toInt() xor 0x01).toByte()

        assertFailsWith<AEADBadTagException> { EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = hybrid.privateKey) }
    }

    @Test
    fun signedHybridV4RejectsUnexpectedMldsaPublicKey() {
        val signer = MlDsa.generateKeyPair()
        val env = EnvelopeCodec.encryptHybrid(
            "authenticated post-quantum".encodeToByteArray(),
            hybrid.publicKey,
            signer,
        )

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decrypt(env, hybrid.privateKey, MlDsa.generateKeyPair().publicKey)
        }
    }

    @Test
    fun hybridEnvelopeWithoutHybridKeyThrows() {
        val env = EnvelopeCodec.encryptHybrid("x".encodeToByteArray(), hybrid.publicKey)
        assertFailsWith<IllegalStateException> { EnvelopeCodec.decrypt(env, rsa.private, hybridPrivate = null) }
    }

    @Test
    fun publicKeySerializationRoundTrips() {
        val bytes = EnvelopeCodec.serializePublicKey(hybrid.publicKey)
        val back = EnvelopeCodec.deserializePublicKey(bytes)
        assertContentEquals(hybrid.publicKey.x25519, back.x25519)
        assertContentEquals(hybrid.publicKey.mlkem, back.mlkem)
        // A serialized-then-deserialized key still encrypts to the original private key.
        val env = EnvelopeCodec.encryptHybrid("y".encodeToByteArray(), back)
        assertContentEquals("y".encodeToByteArray(), HybridKem.decrypt(env, hybrid.privateKey))
    }

    @Test
    fun truncatedPublicKeyRejected() {
        val bytes = EnvelopeCodec.serializePublicKey(hybrid.publicKey)
        assertFailsWith<IllegalArgumentException> { EnvelopeCodec.deserializePublicKey(bytes.copyOf(bytes.size - 10)) }
    }

    @Test
    fun strictSignedHybridDecryption_rejectsAnUnsignedV3Envelope() {
        val expectedSender = MlDsa.generateKeyPair()
        val v3 = EnvelopeCodec.encryptHybrid("downgrade".encodeToByteArray(), hybrid.publicKey)

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decrypt(v3, hybrid.privateKey, expectedSender.publicKey)
        }
    }

    @Test
    fun legacyClassicalStillDecryptsViaCodec() {
        val plain = "legacy vault".encodeToByteArray()
        val v1 = CryptoEnvelope.encryptLegacyV1ForTest(plain, rsa.public)
        assertTrue(v1[0] != 0x50.toByte() || v1[1] != 0x4D.toByte())
        assertContentEquals(plain, EnvelopeCodec.decrypt(v1, rsa.private, hybridPrivate = null))
    }

    // ------------------------------------------------------------ decryptSignedHybrid (strict v4)

    @Test
    fun decryptSignedHybrid_roundTripsAgainstTheExpectedSenderKey() {
        val plain = "strictly authenticated".encodeToByteArray()
        val signer = MlDsa.generateKeyPair()
        val env = EnvelopeCodec.encryptHybrid(plain, hybrid.publicKey, signer)

        assertContentEquals(plain, EnvelopeCodec.decryptSignedHybrid(env, hybrid.privateKey, signer.publicKey))
    }

    @Test
    fun decryptSignedHybrid_rejectsAnUnsignedV3ThatWouldOtherwiseDecryptCleanly() {
        val plain = "downgrade attempt".encodeToByteArray()
        val v3 = EnvelopeCodec.encryptHybrid(plain, hybrid.publicKey)
        // Fixture control: this exact envelope IS decryptable when accepted unsigned. The strict
        // path must reject it anyway — the rejection is about the missing signature, not damage.
        assertContentEquals(plain, HybridKem.decrypt(v3, hybrid.privateKey))

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decryptSignedHybrid(v3, hybrid.privateKey, MlDsa.generateKeyPair().publicKey)
        }
    }

    @Test
    fun decryptSignedHybrid_rejectsAValidV4SignedByADifferentValidKey() {
        // Not a corrupted signature: a completely well-formed envelope from a signer who simply
        // is not the paired device. Only the expected-key comparison can catch this.
        val env = EnvelopeCodec.encryptHybrid(
            "impostor".encodeToByteArray(),
            hybrid.publicKey,
            MlDsa.generateKeyPair(),
        )

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decryptSignedHybrid(env, hybrid.privateKey, MlDsa.generateKeyPair().publicKey)
        }
    }

    @Test
    fun decryptSignedHybrid_rejectsAClassicalV2Envelope() {
        val v2 = EnvelopeCodec.encryptClassical("classical".encodeToByteArray(), rsa.public)
        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decryptSignedHybrid(v2, hybrid.privateKey, MlDsa.generateKeyPair().publicKey)
        }
    }

    // ------------------------------------------------------------ adversarial suite-4 forgeries
    //
    // Everything an attacker needs to build a structurally valid v4 envelope is public: the
    // recipient's hybrid key and the envelope layout. These forgeries pass the GCM layer by
    // construction, so what rejects them is exactly the signature machinery under test.

    @Test
    fun forgedV4WithoutASignatureStructureIsRejected() {
        val env = forgeV4(hybrid.publicKey) { _ -> "no signature block here".encodeToByteArray() }

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decryptSignedHybrid(env, hybrid.privateKey, MlDsa.generateKeyPair().publicKey)
        }
    }

    @Test
    fun forgedV4SignedByOneKeyButEmbeddingAnotherIsRejected() {
        // The attacker signs with their own valid key A but embeds victim key B — the substitution
        // the plan's "substituted sender key inside the envelope" bullet names. The expected-key
        // equality check passes (B is embedded and B is expected), so only the actual ML-DSA
        // verification against the embedded key can reject it.
        val attacker = MlDsa.generateKeyPair()
        val victim = MlDsa.generateKeyPair()
        val payload = "forged payload".encodeToByteArray()
        val env = forgeV4(hybrid.publicKey) { header ->
            val victimKeyHash = MessageDigest.getInstance("SHA-256").digest(victim.publicKey)
            val signature = MlDsa.sign(header + victimKeyHash + payload, attacker.privateSeed)
            signedPlaintextOf(signature, victim.publicKey, payload)
        }

        assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decryptSignedHybrid(env, hybrid.privateKey, victim.publicKey)
        }
    }

    /** Build the inner `sigLen|sig|pubLen|pub|payload` layout without going through HybridKem. */
    private fun signedPlaintextOf(signature: ByteArray, publicKey: ByteArray, payload: ByteArray): ByteArray {
        val out = ByteArray(2 + signature.size + 2 + publicKey.size + payload.size)
        var i = 0
        out[i++] = ((signature.size ushr 8) and 0xFF).toByte()
        out[i++] = (signature.size and 0xFF).toByte()
        signature.copyInto(out, i); i += signature.size
        out[i++] = ((publicKey.size ushr 8) and 0xFF).toByte()
        out[i++] = (publicKey.size and 0xFF).toByte()
        publicKey.copyInto(out, i); i += publicKey.size
        payload.copyInto(out, i)
        return out
    }

    /**
     * Attacker's own suite-4 encryptor: fresh X25519 + ML-KEM to [recipient], HKDF and AES-GCM over
     * whatever inner plaintext [innerPlaintext] produces for the header. Mirrors the public envelope
     * format deliberately — this is the forgery model, not a convenience copy of production code.
     */
    private fun forgeV4(
        recipient: HybridKem.HybridPublicKey,
        innerPlaintext: (header: ByteArray) -> ByteArray,
    ): ByteArray {
        val random = SecureRandom()
        val ephPriv = X25519PrivateKeyParameters(random)
        val ephPub = ephPriv.generatePublicKey().encoded
        val ss1 = ByteArray(32)
        X25519Agreement().apply { init(ephPriv) }
            .calculateAgreement(X25519PublicKeyParameters(recipient.x25519, 0), ss1, 0)
        val encapsulated = MLKEMGenerator(random)
            .generateEncapsulated(MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, recipient.mlkem))
        val kemCt = encapsulated.encapsulation

        val header = ByteArray(4 + 1 + 1 + 32 + 2 + kemCt.size)
        var i = 0
        header[i++] = 0x50; header[i++] = 0x4D; header[i++] = 0x4E; header[i++] = 0x56 // "PMNV"
        header[i++] = 1 // version
        header[i++] = 4 // suite: signed hybrid
        ephPub.copyInto(header, i); i += 32
        header[i++] = ((kemCt.size ushr 8) and 0xFF).toByte()
        header[i++] = (kemCt.size and 0xFF).toByte()
        kemCt.copyInto(header, i)

        val hkdf = HKDFBytesGenerator(SHA256Digest()).apply {
            init(
                HKDFParameters(
                    ss1 + encapsulated.secret,
                    "passman-hybrid-v3".encodeToByteArray(),
                    header + recipient.x25519 + recipient.mlkem,
                ),
            )
        }
        val dek = ByteArray(32).also { hkdf.generateBytes(it, 0, 32) }
        val nonce = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(header)
        }
        return header + nonce + cipher.doFinal(innerPlaintext(header))
    }
}
