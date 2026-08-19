package ai.passman.android.platform.service

import ai.passman.logging.KLogger
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.*
import java.security.interfaces.DSAParams
import java.security.interfaces.DSAPrivateKey
import java.security.interfaces.DSAPublicKey
import java.security.spec.DSAPrivateKeySpec
import java.security.spec.DSAPublicKeySpec
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

private const val KEY_LENGTH = 2048 // 1024 //256 // 2048 //

object KeyService {
    fun createSecretKey(
        keyStoreInfo: KeyStoreInfo,
        keyAlias: String,
        password: CharArray
    ): Key {
        KLogger.i { "new key, $keyAlias" }

        val secretKey = when (keyStoreInfo.type) {
            KeyStoreType.ANDROID -> {
                val keyPair = createAESKey()
                //setAndroidKeyStoreEntry(keyStore, keyAlias, keyPair)
                keyPair
            }
            KeyStoreType.PKCS12 -> {
                val keyPair = createRSAKeys()
                // setPKSC12KeyStoreEntry(keyStore, keyAlias, keyPair, password)
                keyPair.private
            }
            else -> {
                val keyPair = createRSAKeys()
                // setAndroidKeyStoreEntry(keyStore, keyAlias, keyPair)
                keyPair.private
            }
        }

//        when (keyStoreInfo.type) {
//            KeyStoreType.ANDROID -> Unit
//            else -> {
//                val fileOut = FileOutputStream(File(keyStoreInfo.path, keyStoreInfo.name))
//                keyStore?.store(fileOut, password)
//                fileOut.close()
//            }
//        }

        return secretKey
    }

    fun createPublicKey(
        keyStoreInfo: KeyStoreInfo,
        keyAlias: String,
    ): Key {
        KLogger.i { "new key, $keyAlias" }

        val publicKey = when (keyStoreInfo.type) {
            KeyStoreType.ANDROID -> {
                val keyPair = createAESKey() //createRSAKeys()
                //setAndroidKeyStoreEntry(keyStore, keyAlias, keyPair)
                keyPair
            }
            KeyStoreType.PKCS12 -> {
                val keyPair = createRSAKeys()
                val key = keyPair.public
                // setPKSC12KeyStoreEntry(keyStore, keyAlias, keyPair, keyPassword)
                key
            }
            else -> {
                val keyPair = createRSAKeys()
                // val key = createSecretKey(password)
                val key = keyPair.public
                //setAndroidKeyStoreEntry(keyStore, keyAlias, keyPair)
                // setPKSC12KeyStoreEntry(keyStore, keyAlias, keyPair, keyPassword)
                key
            }
        }

        when (keyStoreInfo.type) {
            KeyStoreType.ANDROID -> Unit
            else -> {
                val fileOut = FileOutputStream(File(keyStoreInfo.path, keyStoreInfo.name))
                // keyStore.store(fileOut, keyPassword)
                fileOut.close()
            }
        }

        return publicKey
    }


    fun createRSAKeys(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(KEY_LENGTH, SecureRandom())
        return keyGen.genKeyPair()
//        val publicKey = keypair.public as RSAPublicKey
//        val privateKey = keypair.private as RSAPrivateCrtKey
//
//        val keyFactory = KeyFactory.getInstance("RSA")
//
//        return KeyPair(
//            keyFactory.generatePublic(
//                RSAPublicKeySpec(publicKey.modulus, publicKey.publicExponent)
//            ),
//            keyFactory.generatePrivate(
//                RSAPrivateKeySpec(privateKey.modulus, privateKey.privateExponent)
//            )
//        )
    }

    fun createDSAKeys(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("DSA")
        keyGen.initialize(KEY_LENGTH)
        val keypair = keyGen.genKeyPair()
        val publicKey = keypair.public as DSAPublicKey
        val privateKey = keypair.private as DSAPrivateKey

        val dsaParams: DSAParams = privateKey.params
        val pPrime: BigInteger = dsaParams.p
        val qSubPrime: BigInteger = dsaParams.q
        val gBase: BigInteger = dsaParams.g
        val xPrivateKey: BigInteger = privateKey.x
        val yPublicKey: BigInteger = publicKey.y

        val keyFactory = KeyFactory.getInstance("DSA")

        return KeyPair(
            keyFactory.generatePublic(
                DSAPublicKeySpec(yPublicKey, pPrime, qSubPrime, gBase)
            ),
            keyFactory.generatePrivate(
                DSAPrivateKeySpec(xPrivateKey, pPrime, qSubPrime, gBase)
            )
        )
    }

    fun createDHKeys(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance("DH")
        keyGen.initialize(KEY_LENGTH, SecureRandom())
        return keyGen.genKeyPair()
    }

    // key length must be equal to 128, 192 or 256
    // API Level >=23: Android Keystore available with AES support. Generate a random AES key using into Android Keystore.
    // To encrypt to can use AES/CBC/PKCS7Padding algorithm. It requires also a random initialization vector (IV) to encrypt your data,
    // but it can be public.
    fun createAESKey(): Key {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(KEY_LENGTH, SecureRandom())
        return keyGen.generateKey()
    }

    fun createECKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("ECDH","BC")
        keyPairGenerator.initialize(ECGenParameterSpec("brainpoolp256r1")) // secp521r1 secp256r1 brainpoolP384r1
        return keyPairGenerator.genKeyPair()
    }
}
