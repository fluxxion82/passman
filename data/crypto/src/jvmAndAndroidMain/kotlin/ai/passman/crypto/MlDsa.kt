package ai.passman.crypto

import java.security.SecureRandom
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.signers.MLDSASigner

/** FIPS 204 ML-DSA-65 signing keys and signatures for sync-envelope sender authentication. */
object MlDsa {
    const val PUBLIC_KEY_BYTES = 1_952
    const val PRIVATE_SEED_BYTES = 32
    const val SIGNATURE_BYTES = 3_309

    private val parameters = MLDSAParameters.ml_dsa_65
    private val secureRandom = SecureRandom()

    class KeyPair(val publicKey: ByteArray, val privateSeed: ByteArray)

    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = MLDSAKeyPairGenerator().apply {
            init(MLDSAKeyGenerationParameters(secureRandom, parameters))
        }
        val keyPair = keyPairGenerator.generateKeyPair()
        val publicKey = (keyPair.public as MLDSAPublicKeyParameters).encoded.copyOf()
        val privateKey = keyPair.private as MLDSAPrivateKeyParameters
        return KeyPair(publicKey, privateKey.seed.copyOf())
    }

    fun publicKeyOf(privateSeed: ByteArray): ByteArray {
        require(privateSeed.size == PRIVATE_SEED_BYTES) { "bad ML-DSA-65 private seed length" }
        val seedCopy = privateSeed.copyOf()
        try {
            return MLDSAPrivateKeyParameters(parameters, seedCopy).publicKeyParameters.encoded.copyOf()
        } finally {
            seedCopy.fill(0)
        }
    }

    fun sign(message: ByteArray, privateSeed: ByteArray): ByteArray {
        require(privateSeed.size == PRIVATE_SEED_BYTES) { "bad ML-DSA-65 private seed length" }
        val seedCopy = privateSeed.copyOf()
        try {
            return MLDSASigner().apply {
                init(true, MLDSAPrivateKeyParameters(parameters, seedCopy))
                update(message, 0, message.size)
            }.generateSignature()
        } finally {
            seedCopy.fill(0)
        }
    }

    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != SIGNATURE_BYTES || publicKey.size != PUBLIC_KEY_BYTES) return false
        return MLDSASigner().apply {
            init(false, MLDSAPublicKeyParameters(parameters, publicKey))
            update(message, 0, message.size)
        }.verifySignature(signature)
    }
}
