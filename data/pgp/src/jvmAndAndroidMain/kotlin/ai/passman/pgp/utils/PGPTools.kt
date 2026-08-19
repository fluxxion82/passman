package ai.passman.pgp.utils

import java.io.InputStream
import java.io.OutputStream
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder

object PGPTools {

    fun decryptFile(inputStream: InputStream, out: OutputStream, secretKeyIn: PGPSecretKey, passwd: CharArray) {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(PgpHelper.BOUNCY_PROVIDER, 1)

        val decoderStream = PGPUtil.getDecoderStream(inputStream)
        var pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())
        val encryptedDataList: PGPEncryptedDataList
        val nextObject = pgpObjectFactory.nextObject()

        encryptedDataList = if (nextObject is PGPEncryptedDataList) { nextObject } else { pgpObjectFactory.nextObject() as PGPEncryptedDataList
        }

        encryptedDataList.encryptedDataObjects.forEach { encryptedData ->
            val messageInputStream = when (encryptedData) {
                is PGPPBEEncryptedData -> {
                    val dataDecryptorFactoryBuilder =
                        JcePBEDataDecryptorFactoryBuilder().setProvider(PgpHelper.BOUNCY_PROVIDER).build(passwd)
                    encryptedData.getDataStream(dataDecryptorFactoryBuilder)
                }
                is PGPPublicKeyEncryptedData -> {
                    val sKey = PgpKeys.getPrivateKey(secretKeyIn, passwd.toString()) // findSecretKey(secretKeyIn, encryptedData.keyID, passwd)
                    requireNotNull(sKey) { "Secret key for message not found." }
                    val dataDecryptorFactoryBuilder =
                        JcePublicKeyDataDecryptorFactoryBuilder()
                            .setProvider(PgpHelper.BOUNCY_PROVIDER)
                            .setContentProvider(PgpHelper.BOUNCY_PROVIDER)
                            .build(sKey)
                    encryptedData.getDataStream(dataDecryptorFactoryBuilder)
                }
                else -> throw PGPException("message unknown message type.")
            }

            pgpObjectFactory = PGPObjectFactory(messageInputStream, BcKeyFingerprintCalculator())
            var messageObject: Any = pgpObjectFactory.nextObject()
            if (messageObject is PGPCompressedData) {
                val compressedData = messageObject
                messageObject = PGPObjectFactory(compressedData.dataStream, BcKeyFingerprintCalculator()).nextObject()
            }
            when (messageObject) {
                is PGPLiteralData -> {
                    val unc = messageObject.inputStream
                    var ch: Int
                    while (unc.read().also { ch = it } >= 0) {
                        out.write(ch)
                    }
                }
                is PGPOnePassSignatureList -> {
                    throw PGPException("Encrypted message contains a signed message - not literal data.")
                }
                else -> {
                    throw PGPException("Message is not a simple encrypted file - type unknown.")
                }
            }

            if (encryptedData.isIntegrityProtected) {
                if (!encryptedData.verify()) {
                    throw PGPException("Message failed integrity check")
                }
            }
        }
    }

}
