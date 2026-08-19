package ai.passman.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * FIPS-203 conformance + regression checks for the ML-KEM-768 primitive [HybridKem] builds on.
 * BouncyCastle 1.85's ML-KEM is CAVP-validated; these tests pin the standard's fixed sizes and
 * exercise the deterministic encapsulation path so any library drift or misuse is caught.
 *
 * NOTE: full NIST ACVP known-answer hex vectors (deterministic keygen from (d,z) seeds → exact
 * ek/dk/ct/ss) are the gold standard and remain a follow-up; they need the published vector files.
 */
class MlKem768KatTest {
    private val params = MLKEMParameters.ml_kem_768

    private fun keyPair() =
        MLKEMKeyPairGenerator().apply {
            init(MLKEMKeyGenerationParameters(SecureRandom(), params))
        }.generateKeyPair()

    @Test
    fun fips203FixedSizes() {
        val kp = keyPair()
        val pub = kp.public as MLKEMPublicKeyParameters
        assertEquals(1184, pub.encoded.size, "ML-KEM-768 encapsulation key (ek) is 1184 bytes")

        val enc = MLKEMGenerator(SecureRandom()).generateEncapsulated(pub)
        assertEquals(1088, enc.encapsulation.size, "ciphertext (c) is 1088 bytes")
        assertEquals(32, enc.secret.size, "shared secret (K) is 32 bytes")
    }

    @Test
    fun deterministicEncapsulationIsRepeatable() {
        val pub = keyPair().public as MLKEMPublicKeyParameters
        val m = ByteArray(32) { 0x42 }
        val a = MLKEMGenerator.internalGenerateEncapsulated(pub, m)
        val b = MLKEMGenerator.internalGenerateEncapsulated(pub, m)
        assertContentEquals(a.encapsulation, b.encapsulation, "same key+message -> same ciphertext")
        assertContentEquals(a.secret, b.secret, "same key+message -> same shared secret")
    }

    @Test
    fun encapsulateDecapsulateAgree() {
        val kp = keyPair()
        val enc = MLKEMGenerator(SecureRandom()).generateEncapsulated(kp.public as MLKEMPublicKeyParameters)
        val recovered = MLKEMExtractor(kp.private as MLKEMPrivateKeyParameters).extractSecret(enc.encapsulation)
        assertContentEquals(enc.secret, recovered, "decapsulated secret matches encapsulated secret")
    }

    @Test
    fun differentMessagesGiveDifferentCiphertext() {
        val pub = keyPair().public as MLKEMPublicKeyParameters
        val a = MLKEMGenerator.internalGenerateEncapsulated(pub, ByteArray(32) { 1 })
        val b = MLKEMGenerator.internalGenerateEncapsulated(pub, ByteArray(32) { 2 })
        assertFalse(a.encapsulation.contentEquals(b.encapsulation))
    }

    @Test
    fun wrongKeyDecapsulatesToDifferentSecret() {
        // ML-KEM implicit rejection: decapsulating with the wrong key yields a pseudo-random secret
        // (never an error). HybridKem relies on this surfacing downstream as a GCM tag failure.
        val kpA = keyPair()
        val kpB = keyPair()
        val enc = MLKEMGenerator(SecureRandom()).generateEncapsulated(kpA.public as MLKEMPublicKeyParameters)
        val wrong = MLKEMExtractor(kpB.private as MLKEMPrivateKeyParameters).extractSecret(enc.encapsulation)
        assertFalse(enc.secret.contentEquals(wrong))
    }
}
