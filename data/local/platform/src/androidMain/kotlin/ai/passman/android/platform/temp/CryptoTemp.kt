package ai.passman.android.platform.temp

import ai.passman.logging.KLogger
import android.os.Build
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.io.ByteArrayInputStream
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class CryptoTemp {
    fun importAESKey(keyStoreAlias: String, password: CharArray) {
        val keyStore = KeyStore.getInstance(
            "AES",
            "AndroidKeyStore"
        )
        val key = createSecretKey(password)
        keyStore.load(null)
//        keyStore.setEntry(
//            keyStoreAlias,
//            KeyStore.SecretKeyEntry(key),
//            KeyProtection.Builder(KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                .build()
//        )
        // Key imported, obtain a reference to it.
        val keyStoreKey = keyStore.getKey(keyStoreAlias, null)
        // The original key can now be discarded.

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keyStoreKey)
    }

    fun importHMACKey(keyStoreAlias: String, password: CharArray) {
        val keyStore = KeyStore.getInstance(
            ENCRYPTION_HMAC_SHA512_ALGORITHM,
            ANDROID_KEYSTORE
        )

        // HMAC key of algorithm "HmacSHA512".
        val key = createSecretKey(password)
        keyStore.load(null)
//        keyStore.setEntry(
//            keyStoreAlias,
//            KeyStore.SecretKeyEntry(key),
//            KeyProtection.Builder(KeyProperties.PURPOSE_SIGN).build()
//        )
        // Key imported, obtain a reference to it.
        val keyStoreKey = keyStore.getKey(keyStoreAlias, null)
        // The original key can now be discarded.

        val mac = Mac.getInstance("HmacSHA512")
        mac.init(keyStoreKey)
    }

    fun importECKey(keyStoreAlias: String) {
        val privateKey: PrivateKey? = null // EC private key
        val certChain: Array<Certificate> =
            arrayOf() // Certificate chain with the first certificate
        // containing the corresponding EC public key.

        val keyStore = KeyStore.getInstance(
            ENCRYPTION_EC_ALGORITHM,
            ANDROID_KEYSTORE
        )
        keyStore.load(null)
//        keyStore.setEntry(
//            keyStoreAlias,
//            KeyStore.PrivateKeyEntry(privateKey, certChain),
//            KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
//                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
//                .build()
//        )

        // Key pair imported, obtain a reference to it.
        val keyStorePrivateKey = keyStore.getKey(keyStoreAlias, null) as PrivateKey
        val publicKey = keyStore.getCertificate(keyStoreAlias).publicKey

        // The original private key can now be discarded.
        val signature: Signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(keyStorePrivateKey)
    }

    fun importRSAUsingPKCS1ForSignVerify(keyStoreAlias: String) {
        val privateKey: PrivateKey? = null // RSA private key
        val certChain: Array<Certificate> =
            arrayOf() // Certificate chain with the first certificate
        // containing the corresponding RSA public key.

        val keyStore = KeyStore.getInstance(
            ENCRYPTION_RSA_ALGORITHM,
            ANDROID_KEYSTORE
        )
        keyStore.load(null)
//        keyStore.setEntry(
//            keyStoreAlias,
//            KeyStore.PrivateKeyEntry(privateKey, certChain),
//            KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
//                .setDigests(KeyProperties.DIGEST_SHA256)
//                .setSignaturePaddings(ENCRYPTION_RSA_PKCS1_SIGNATURE)
//                // Only permit this key to be used if the user
//                // authenticated within the last ten minutes.
//                .setUserAuthenticationRequired(true)
//                // .setUserAuthenticationValidityDurationSeconds(10 * 60)
//                .build()
//        )
        // Key pair imported, obtain a reference to it.
        val keyStorePrivateKey = keyStore.getKey(keyStoreAlias, null) as PrivateKey
        val publicKey = keyStore.getCertificate(keyStoreAlias).publicKey
        // The original private key can now be discarded.

        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(keyStorePrivateKey)
    }

    fun importRSAUsingPKCS1ForDecrypt(keyStoreAlias: String) {
        val privateKey: PrivateKey? = null // RSA private key
        val certChain: Array<Certificate> = arrayOf() // Certificate chain w/ the first certificate

        // containing the corresponding RSA public key.
        val keyStore = KeyStore.getInstance(
            ENCRYPTION_RSA_ALGORITHM,
            ANDROID_KEYSTORE
        )
        keyStore.load(null)
//        keyStore.setEntry(
//            keyStoreAlias,
//            KeyStore.PrivateKeyEntry(privateKey, certChain),
//            KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
//                .build()
//        )
        // Key pair imported, obtain a reference to it.
        val keyStorePrivateKey = keyStore.getKey(keyStoreAlias, null)
        val publicKey = keyStore.getCertificate(keyStoreAlias).publicKey
        // The original private key can now be discarded.
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, keyStorePrivateKey)
    }

    fun getKeyChainPrivateKey(keyStoreAlias: String) {
//        val pk = KeyChain.getPrivateKey(context, keyStoreAlias)
//        val chain = KeyChain.getCertificateChain(context, keyStoreAlias)
//
//        val data = "foobar".toByteArray(charset("ASCII"))
//        val sig = Signature.getInstance("SHA1withRSA")
//        sig.initSign(pk)
//        sig.update(data)
//        val signed = sig.sign()
//
//        val pubKey = chain!![0].publicKey
//        sig.initVerify(pubKey)
//        sig.update(data)
//        val valid = sig.verify(signed)
    }

    fun getListOfCerts(): MutableList<Certificate> {
        val certs = mutableListOf<Certificate>()
        val keyStore = KeyStore.getInstance(ANDROID_CA_STORE)
        keyStore.load(null, null)
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            val cert = keyStore.getCertificate(alias) as X509Certificate
            certs.add(cert)
            KLogger.d { "Subject DN: ${cert.subjectDN.name}" }
            KLogger.d { "Issuer DN: ${cert.issuerDN.name}" }
        }
        return certs
    }

    fun validateCerts(keyStoreAlias: String) {
//        val chain = KeyChain.getCertificateChain(context, keyStoreAlias)
//        if (chain != null) {
//            for (x in chain) {
//                KLogger.d { "Subject DN: ${x.subjectDN.name}" }
//                KLogger.d { "Issuer DN: ${x.issuerDN.name}" }
//            }
//        }

        val tmf: TrustManagerFactory = TrustManagerFactory.getInstance("X509")
        tmf.init(null as KeyStore?)

        val tms: Array<TrustManager> = tmf.trustManagers
        val xtm: X509TrustManager = tms[0] as X509TrustManager

        KLogger.d { "checking chain with $xtm" }
        // xtm.checkClientTrusted(chain, "RSA")
        KLogger.d { "chain is valid" }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun certificateFromString(base64: String): X509Certificate {
        val decoded = Base64.getDecoder().decode(base64)
        val inputStream = ByteArrayInputStream(decoded)

        return CertificateFactory.getInstance("X.509")
            .generateCertificate(inputStream) as X509Certificate
    }

    private fun createCert(trusedCertStr: String) {
        val certFactory: CertificateFactory = CertificateFactory.getInstance("X.509")

        val inputStream = ByteArrayInputStream(trusedCertStr.toByteArray())
        val trustedCert: Certificate = certFactory.generateCertificate(inputStream)
        inputStream.close()
    }

    private fun generatePrivateKeyPair(): KeyPair {
        var keyPair = createPrivateKey()
        var nPublicExponent = 3
        while (nPublicExponent <= 65537) {
            keyPair = createPrivateKey()
            val publicKey = keyPair.public
            val privateKey = keyPair.private

            if (publicKey == null) {
                nPublicExponent++
                continue
            }
            val encryptMessage = testEncrypt("hello", publicKey)
            if (encryptMessage == null) {
                nPublicExponent++
                continue
            }
            val sMessage = testDecrypt(encryptMessage, privateKey)
            if (sMessage.isNullOrEmpty()) {
                nPublicExponent++
                continue
            }
            if (sMessage == "hello") {
                break
            }
            nPublicExponent++
        }

        return keyPair
    }

    fun createPrivateKey(): KeyPair =
        KeyPairGenerator.getInstance("RSA").genKeyPair()

    fun createSecretKey(password: CharArray): SecretKey =
        KeyGenerator.getInstance("AES").generateKey()

    fun loadKeyStore(param: String, param2: String, param3: CharArray) = KeyStore.getDefaultType()

    fun rsaCert() {
//        val rsa = Rsa()
//        val cert = Certificate(CertStoreTypes.cstPFXFile, certificateFilePath, "test", "*")
//        rsa.RecipientCert = cert
//        rsa.InputMessage = "Encrypt me please!"
//        rsa.Encrypt()
    }

    var tempIV: ByteArray? = null
    fun testEncrypt(sMessage: String, publicKey: Key): ByteArray? {
        return try {
            val encrypt = Cipher.getInstance(
                "RSA/ECB/PKCS5Padding"
                // "AES/CBC/PKCS7Padding"
            )
            encrypt.init(Cipher.ENCRYPT_MODE, publicKey)
            encrypt.doFinal(sMessage.toByteArray()).also {
                tempIV = encrypt.iv
            }
        } catch (ex: Exception) {
            null
        }
    }

    fun testDecrypt(encryptedMessage: ByteArray?, privateKey: Key, iv: ByteArray? = null): String? {
        return try {
            val decrypt = Cipher.getInstance(
                "RSA/ECB/PKCS5Padding"
                // "AES/CBC/PKCS7Padding"
            )
            decrypt.init(Cipher.DECRYPT_MODE, privateKey, IvParameterSpec(iv))
            String(decrypt.doFinal(encryptedMessage))
        } catch (ex: Exception) {
            null
        }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ANDROID_CA_STORE = "AndroidCAStore"
        private const val KEY_ALIAS = "passman_key"

        private const val PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1"

        private const val ENCRYPTION_BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val ENCRYPTION_PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val ENCRYPTION_AES_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES

        private const val ENCRYPTION_RSA_PKCS1_SIGNATURE = KeyProperties.SIGNATURE_PADDING_RSA_PKCS1

        private const val ENCRYPTION_HMAC_SHA512_ALGORITHM = KeyProperties.KEY_ALGORITHM_HMAC_SHA512
        private const val ENCRYPTION_EC_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        private const val ENCRYPTION_RSA_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
    }
}
