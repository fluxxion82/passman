package ai.passman.pgp.utils

import java.io.OutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.util.*
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.RSASecretBCPGKey
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter

class RSAKeyPairGenerator {
    fun exportKeyPair(
        secretOut: OutputStream,
        publicOut: OutputStream,
        publicKey: PublicKey?,
        privateKey: PrivateKey,
        identity: String?,
        passPhrase: CharArray?,
        armor: Boolean
    ) {
        var publicOutStream = publicOut
        val secretOutStream = if (armor) {
            ArmoredOutputStream(secretOut)
        } else {
            secretOut
        }
        val public =
            JcaPGPKeyConverter().getPGPPublicKey(PublicKeyPacket.VERSION_4, PGPPublicKey.RSA_GENERAL, publicKey, Date())
        val rsK = privateKey as RSAPrivateCrtKey
        val privPk = RSASecretBCPGKey(rsK.privateExponent, rsK.primeP, rsK.primeQ)
        val private = PGPPrivateKey(public.keyID, public.publicKeyPacket, privPk)
        // bcpg only supports SHA-1 for the secret-key checksum; the S2K digest is SHA-256.
        val sha1Calc: PGPDigestCalculator = JcaPGPDigestCalculatorProviderBuilder().build()[HashAlgorithmTags.SHA1]
        val keyPair = PGPKeyPair(public, private)
        val secretKey = PGPSecretKey(
            PGPSignature.DEFAULT_CERTIFICATION,
            keyPair,
            identity,
            sha1Calc,
            null,
            null,
            JcaPGPContentSignerBuilder(keyPair.publicKey.algorithm, HashAlgorithmTags.SHA256),
            PgpKeys.createSecretKeyEncryptor(passPhrase ?: CharArray(0))
        )
        secretKey.encode(secretOutStream)
        secretOutStream.close()
        if (armor) {
            publicOutStream = ArmoredOutputStream(publicOut)
        }
        val key = secretKey.publicKey
        key.encode(publicOutStream)
        publicOutStream.close()
    }

//    fun createKey(algorithmChoice: String, keySize: Int, passPhrase: String?, masterKey: PGPSecretKey?): PGPSecretKey? {
//        var passPhrase = passPhrase
//        if (keySize < 512) {
//            // throw GeneralException(context.getString(R.string.error_keySizeMinimum512bit))
//        }
//        if (passPhrase == null) {
//            passPhrase = ""
//        }
//        var algorithm = 0
//        var keyGen: KeyPairGenerator? = null
//        when (algorithmChoice) {
//            "Id.choice.algorithm.dsa" -> {
//                keyGen = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider())
//                keyGen.initialize(keySize, SecureRandom())
//                algorithm = PGPPublicKey.DSA
//            }
//            "Id.choice.algorithm.elgamal" -> {
//                if (masterKey == null) {
//                    throw Exception("masterKeyMustNotBeElGamal")
//                }
//                keyGen = KeyPairGenerator.getInstance("ELGAMAL", BouncyCastleProvider())
//                val p: BigInteger = Primes.getBestPrime(keySize)
//                val g = BigInteger("2")
//                val elParams = ElGamalParameterSpec(p, g)
//                keyGen.initialize(elParams)
//                algorithm = PGPPublicKey.ELGAMAL_ENCRYPT
//            }
//            "Id.choice.algorithm.rsa" -> {
//                keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider())
//                keyGen.initialize(keySize, SecureRandom())
//                algorithm = PGPPublicKey.RSA_GENERAL
//            }
//            else -> {
//                throw Exception("unknownAlgorithmChoice")
//            }
//        }
//        val keyPair = PGPKeyPair()//algorithm, keyGen.generateKeyPair(), Date())
//        var secretKey: PGPSecretKey? = null
//        if (masterKey == null) {
//            // enough for now, as we assemble the key again later anyway
//            secretKey = PGPSecretKey(
//                PGPSignature.DEFAULT_CERTIFICATION,
//                keyPair,
//                identity,
//                sha1Calc,
//                null,
//                null,
//                JcaPGPContentSignerBuilder(keyPair.publicKey.algorithm, HashAlgorithmTags.SHA1),
//                JcePBESecretKeyEncryptorBuilder(
//                    PGPEncryptedData.CAST5, sha1Calc
//                ).setProvider("BC").build(passPhrase)
//            )
//        } else {
//            val tmpKey = masterKey.publicKey
//            val masterPublicKey = PGPPublicKey(tmpKey.algorithm, tmpKey.getKey(BouncyCastleProvider()), tmpKey.creationTime)
//            val masterPrivateKey = masterKey.extractPrivateKey(passPhrase.toCharArray(), BouncyCastleProvider())
//            val masterKeyPair = PGPKeyPair(masterPublicKey, masterPrivateKey)
//            val ringGen = PGPKeyRingGenerator(
//                PGPSignature.POSITIVE_CERTIFICATION,
//                masterKeyPair,
//                "",
//                PGPEncryptedData.CAST5,
//                passPhrase.toCharArray(),
//                null,
//                null,
//                SecureRandom(),
//                BouncyCastleProvider().name
//            )
//            ringGen.addSubKey(keyPair)
//            val secKeyRing = ringGen.generateSecretKeyRing()
//            val it: Iterator<*> = secKeyRing.secretKeys
//            // first one is the master key
//            it.next()
//            secretKey = it.next() as PGPSecretKey?
//        }
//        return secretKey
//    }
}
