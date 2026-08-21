package ai.passman.pgp.service

import ai.passman.keys.model.DSA
import ai.passman.keys.model.ELGAMAL
import ai.passman.keys.model.RSA
import ai.passman.pgp.utils.PgpHelper
import ai.passman.pgp.utils.PgpKeys
import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.UserIdAction
import java.io.*
import java.util.*
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder

class PgpClient {
    fun getPublicKey(filePath: String): Result<PGPPublicKey> {
        return runCatching {
            PgpKeys.readPublicKey(filePath)
        }.onFailure {
            KLogger.e(it) {
                "failed to read public key: ${it.message}"
            }
        }
    }

    fun getSecretKey(filePath: String): Result<PGPSecretKey> {
        return runCatching {
            PgpKeys.readSecretKey(filePath)
        }.onFailure {
            KLogger.e(it) {
                "failed to read secret key: ${it.message}"
            }
        }
    }

    fun encryptPgpMessage(plainText: String, publicKeyPath: String): Outcome<String> {
        return runCatching {
            KLogger.d { "encryptPgpMessage" }
            val encryptOutput = ByteArrayOutputStream()

            // The plaintext secret is briefly staged to a temp file for the OpenPGP
            // literal-data generator. Restrict it to the owner and guarantee deletion so
            // the cleartext never lingers in the system temp dir.
            val plain = File.createTempFile("plaintext", ".txt").apply {
                setReadable(false, false)
                setReadable(true, true)
                setWritable(false, false)
                setWritable(true, true)
                deleteOnExit()
            }
            try {
                plain.writeText(plainText)

                val pubKey = PgpKeys.readPublicKey(publicKeyPath)
                pubKey.let { PgpHelper.encryptFile(encryptOutput, plain, it, armor = true, withIntegrityCheck = true) }
            } finally {
                plain.delete()
            }

            val encrypted = ByteArrayInputStream(encryptOutput.toByteArray())

            val contentBuilder = StringBuilder()
            BufferedReader(InputStreamReader(encrypted)).use { br ->
                var line: String?
                while (br.readLine().also { line = it } != null) {
                    contentBuilder.append(line).append("\n")
                }
            }

            Outcome.Success(contentBuilder.toString())
        }.onFailure {
            KLogger.e(it) { "failed to encrypt, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to encrypt", PgpFailure.GeneralPgpError("failed to encrypt"))
        )
    }

    fun encryptPgpFile(filePath: String, newFilePath: String, publicKeyPath: String): Outcome<String> {
        return runCatching {
            KLogger.d { "encrypt: $filePath" }
            val pubKey = PgpKeys.readPublicKey(publicKeyPath)
            val plainFile = File(filePath)

            val encryptedFile = File(newFilePath)
            val encryptOutputStream = FileOutputStream(encryptedFile)

            PgpHelper.encryptFile(encryptOutputStream, plainFile, pubKey, armor = true, withIntegrityCheck = true)

            Outcome.Success(encryptedFile.absolutePath)
        }.onFailure {
            KLogger.e(it) { "failed to encrypt, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to encrypt", PgpFailure.GeneralPgpError("failed to encrypt"))
        )
    }

    fun decryptPgpMessage(encryptedText: String, secretKeyPath: String, keyPassword: String): Outcome<String> {
        return runCatching {
            val cryptedText = ByteArrayInputStream(encryptedText.toByteArray())

            val plainText = ByteArrayOutputStream()
            val secretKey = PgpKeys.loadSecretKeyRing(secretKeyPath)
            PgpHelper.decryptFile(cryptedText, plainText, secretKey, keyPassword)

            val plain = ByteArrayInputStream(plainText.toByteArray())

            val contentBuilder = StringBuilder()
            BufferedReader(InputStreamReader(plain)).use { br ->
                var line: String?
                while (br.readLine().also { line = it } != null) {
                    contentBuilder.append(line).append("\n")
                }
                contentBuilder.deleteAt(contentBuilder.indexOf(contentBuilder.last()))
            }

            Outcome.Success(contentBuilder.toString())
        }.onFailure {
            KLogger.e(it) { "failed to decrypt message, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to decrypt message", PgpFailure.DecryptFailure)
        )
    }

    fun decryptPgpFile(encryptedFilePath: String, newFilePath: String, secretKeyPath: String, keyPassword: String): Outcome<String> {
        return runCatching {
            val encryptedFile = File(encryptedFilePath)
            val fileInputStream = FileInputStream(encryptedFile)

            val decryptedFile = File(newFilePath) // createNewFileWithAppendedName(encryptedFilePath, "decrypted")
            val decryptedStream = FileOutputStream(decryptedFile)
            val secretKey = PgpKeys.loadSecretKeyRing(secretKeyPath)
            PgpHelper.decryptFile(fileInputStream, decryptedStream, secretKey, keyPassword)

            Outcome.Success(decryptedFile.absolutePath)
        }.onFailure {
            KLogger.e(it) { "failed to decrypt message, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to decrypt message", PgpFailure.DecryptFailure)
        )
    }

    fun clearSign(plainText: String, privateKeyPath: String, keyPassword: String): Outcome<String> {
        return runCatching {
                val privKey = PgpKeys.readSecretKey(privateKeyPath)

                val text = StringBuilder(plainText).append("\n").toString()

                Outcome.Success(
                    String(PgpHelper.clearSign(text.toByteArray(), privKey, keyPassword.toCharArray(), "SHA512"))
                )
            }.onFailure {
                KLogger.e(it) { "failed to sign" }
            }.getOrDefault(
                Outcome.Error("failed to sign", PgpFailure.SignFailure)
            )
        }

    fun clearSignFile(plainFilePath: String, newFilePath: String, privateKeyPath: String, keyPassword: String): Outcome<String> {
        return runCatching {
            val privKey = PgpKeys.readSecretKey(privateKeyPath)
            val fileToSign = File(plainFilePath)
            fileToSign.appendBytes("\n".encodeToByteArray())
            val signed = PgpHelper.clearSign(fileToSign.readBytes(), privKey, keyPassword.toCharArray(), "SHA512")
            val signedFile = File(newFilePath) // createNewFileWithAppendedName(plainFilePath, "signed")
            signedFile.writeBytes(signed)
            Outcome.Success(signedFile.absolutePath)
        }.onFailure {
            KLogger.e(it) { "failed to sign" }
        }.getOrDefault(
            Outcome.Error("failed to sign", PgpFailure.SignFailure)
        )
    }

    fun sign(
        plainText: String,
        privateKeyPath: String,
        passPhrase: String,
        armor: Boolean,
        digestName: String
    ): Outcome<String> {
        return runCatching {
            val privKey = PgpKeys.readSecretKey(privateKeyPath)

            val text = StringBuilder(plainText).append("\n").toString()

            Outcome.Success(
                String(PgpHelper.sign(text.toByteArray(), privKey, passPhrase, armor, digestName))
            )
        }.onFailure {
            KLogger.e(it) { "failed to sign, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to sign", PgpFailure.SignFailure)
        )
    }

    fun verifyClearSignature(encryptedText: String, publicKeyPath: String): Outcome<Unit> {
        return runCatching {
            val text = StringBuilder(encryptedText).append("\n").toString()

            if (PgpHelper.verifyClearSign(text.toByteArray(), publicKeyPath)) {
                Outcome.Success(Unit)
            } else {
                Outcome.Error("failed to verify clear signature", PgpFailure.SignVerifyFailure)
            }
        }.onFailure {
            KLogger.e(it) { "failed to verify clear signature, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to verify clear signature", PgpFailure.SignVerifyFailure)
        )
    }

    fun verifyClearSignatureFile(filePath: String, publicKeyPath: String): Outcome<Unit> {
        return runCatching {
            val file = File(filePath)
            file.appendBytes("\n".encodeToByteArray())
            if (PgpHelper.verifyClearSign(file.readBytes(), publicKeyPath)) {
                Outcome.Success(Unit)
            } else {
                Outcome.Error("failed to verify clear signature", PgpFailure.SignVerifyFailure)
            }
        }.onFailure {
            KLogger.e(it) { "failed to verify clear signature, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to verify clear signature", PgpFailure.SignVerifyFailure)
        )
    }

    fun verifySignature(signatureText: String, publicKeyPath: String): Outcome<Unit> {
        return runCatching {
            val text = StringBuilder(signatureText).append("\n").toString()

            if (PgpHelper.verifySignature(text.toByteArray(), publicKeyPath)) {
                Outcome.Success(Unit)
            } else {
                Outcome.Error("failed to verify signature", PgpFailure.SignVerifyFailure)
            }
        }.onFailure {
            KLogger.e(it) { "failed to verify signature, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("failed to verify signature", PgpFailure.SignVerifyFailure)
        )
    }

    fun signAndEncrypt(
        plainText: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String
    ): Outcome<String> {
        return runCatching {
            val privateKeyIn = PgpKeys.readSecretKey(privateKeyPath)
            val publicKeyIn = PgpKeys.readPublicKey(publicKeyPath)

            val text = StringBuilder(plainText).append("\n").toString()

            Outcome.Success(
                String(PgpHelper.signAndEncrypt(text.toByteArray(), privateKeyIn, keyPassword, publicKeyIn, true))
            )
        }.onFailure {
            KLogger.e(it) { "Failed to sign and encrypt, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("Failed to sign and encrypt", PgpFailure.SignAndEncryptFailure)
        )
    }

    fun signAndEncryptFile(
        plainFilePath: String,
        newFilePath: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String
    ): Outcome<String> {
        return runCatching {
            val privateKeyIn = PgpKeys.readSecretKey(privateKeyPath)
            val publicKeyIn = PgpKeys.readPublicKey(publicKeyPath)

            val plainFile = File(plainFilePath)
            plainFile.appendBytes("\n".encodeToByteArray())

            // val encryptedFile = createNewFileWithAppendedName(plainFilePath, "encrypted_signed")
            val encryptedFile = File(newFilePath)
            val resultBytes = PgpHelper.signAndEncrypt(plainFile.readBytes(), privateKeyIn, keyPassword, publicKeyIn, true)
            encryptedFile.writeBytes(resultBytes)

            Outcome.Success(encryptedFile.absolutePath)
        }.onFailure {
            KLogger.e(it) { "Failed to sign and encrypt, ${it.message}" }
        }.getOrDefault(
            Outcome.Error("Failed to sign and encrypt", PgpFailure.SignAndEncryptFailure)
        )
    }

    fun verifyAndDecrypt(
        encryptedText: String,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String
    ): Outcome<String> {
        return runCatching {
            val secretRing = PgpKeys.loadSecretKeyRing(privateKeyPath)

            val text = StringBuilder(encryptedText).append("\n").toString()

            Outcome.Success(
                String(PgpHelper.decryptAndVerify(text.toByteArray(), secretRing, keyPassword, publicKeyPath))
            )
        }.onFailure {
            KLogger.e(it) { it.message ?: "failed to decrypt and verify, ${it.message}" }
        }.getOrNull() ?: Outcome.Error("Failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
    }

    fun verifyAndDecryptFile(
        encryptedFilePath: String,
        newFile: File,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String
    ): Outcome<String> {
        return runCatching {
            val secretRing = PgpKeys.loadSecretKeyRing(privateKeyPath)

            val encrypted = File(encryptedFilePath)

            val resultBytes = PgpHelper.decryptAndVerify(encrypted.readBytes(), secretRing, keyPassword, publicKeyPath)
            newFile.writeBytes(resultBytes)
            Outcome.Success(newFile.absolutePath)
        }.onFailure {
            KLogger.e(it) { it.message ?: "failed to decrypt and verify, ${it.message}" }
        }.getOrNull() ?: Outcome.Error("Failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
    }

    fun getSecretKeyRing(filePath: String, password: String): PGPSecretKeyRing {
        val keyRingFile = File(filePath)
        return PgpKeys.getSecretKeyRing(keyRingFile.readBytes(), password)
    }

    fun getPublicKeyRing(filePath: String): PGPPublicKeyRing {
        val keyRingFile = File(filePath)
        return PgpKeys.getPublicKeyRing(keyRingFile.readBytes())
    }

    fun createKeyPair(): PGPKeyPair {
        return PgpKeys.createKeyPair(4096, RSA)
    }

    fun addPgpKeyPairToRings(
        pgpPublicRing: PGPPublicKeyRing,
        pgpSecretRing: PGPSecretKeyRing,
        keyPair: PGPKeyPair,
        email: String,
        password: String,
    ) {
        PgpKeys.addNewKeyPairToSecretRing(pgpSecretRing, keyPair, email, password.toCharArray())
        PgpKeys.addPublicKeyToRing(pgpPublicRing, keyPair)
    }

    fun modifyUserId(keyPair: PgpKeyPair, userId: String, password: String, action: UserIdAction) {
        val secretKeyRing = getSecretKeyRing(keyPair.secretKey!!.path, password)
        val publicKeyRing = getPublicKeyRing(keyPair.publicKey.path)

        val secretKey = secretKeyRing.secretKey
        val publicKey = publicKeyRing.publicKey

        val newPublicKey = if (action != UserIdAction.REMOVE) {
            val pgpPrivateKey = secretKey!!.extractPrivateKey(
                JcePBESecretKeyDecryptorBuilder()
                    .setProvider("BC").build(password.toCharArray())
            )

            val signerBuilder = JcaPGPContentSignerBuilder(publicKey.algorithm, HashAlgorithmTags.SHA256)
            val signatureGenerator = PGPSignatureGenerator(signerBuilder, publicKey)

            if (action == UserIdAction.REVOKE) {
                signatureGenerator.init(PGPSignature.CERTIFICATION_REVOCATION, pgpPrivateKey)
            } else {
                signatureGenerator.init(PGPSignature.POSITIVE_CERTIFICATION, pgpPrivateKey)
            }

            val updatedSignature = signatureGenerator.generateCertification(userId, publicKey)

            PGPPublicKey.addCertification(publicKey, userId, updatedSignature)
        } else {
            PGPPublicKey.removeCertification(publicKey, userId)
        }

        updateKeyRingsWithNewKey(
            newPublicKey = newPublicKey,
            secretKey = secretKey,
            publicKeyRing = publicKeyRing,
            secretKeyRing = secretKeyRing,
            publicKeyPath = keyPair.publicKey.path,
            secretKeyPath = keyPair.secretKey!!.path,
        )
    }

    fun addSubKey(
        keyPair: PgpKeyPair,
        passphrase: String,
        algorithm: String,
        length: Int,
        keyFlags: Int,
        expirationTimeInSeconds: Long,
    ) {
        val secretKeyRing = getSecretKeyRing(keyPair.secretKey!!.path, passphrase)
        val publicKeyRing = getPublicKeyRing(keyPair.publicKey.path)

        val secretKey = secretKeyRing.secretKey
        val publicKey = publicKeyRing.publicKey

        val algo = when (algorithm) {
            "RSA" -> RSA
            "DSA" -> DSA
            "ElGamal" -> ELGAMAL
            else -> RSA
        }
        val newKeyPair = PgpKeys.createKeyPair(length, algo)
        val contentSignerBuilder: PGPContentSignerBuilder =
            BcPGPContentSignerBuilder(
                publicKey.algorithm,
                HashAlgorithmTags.SHA512,
//                when (algorithm) {
//                    "RSA" -> PublicKeyAlgorithmTags.RSA_GENERAL
//                    // "DSA" -> PublicKeyAlgorithmTags.DSA
//                    else -> PublicKeyAlgorithmTags.RSA_GENERAL
//                },
//                HashAlgorithmTags.SHA512,
            )

        val subPacketGenerator = PGPSignatureSubpacketGenerator()
        subPacketGenerator.setKeyFlags(false, keyFlags)
        if (expirationTimeInSeconds > 0) {
            subPacketGenerator.setKeyExpirationTime(false, expirationTimeInSeconds)
        }

        val provider = BcPGPDigestCalculatorProvider()
        // bcpg only supports SHA-1 for the secret-key checksum; the S2K digest is SHA-256.
        val sha1Calc = provider[HashAlgorithmTags.SHA1]

        val pgpPrivateKey = secretKey!!.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(provider).build(passphrase.toCharArray())
        )

        val secretKeyEncryptor = PgpKeys.createSecretKeyEncryptor(passphrase.toCharArray())

        val signatureSubpacketVector = subPacketGenerator.generate()

        val newSubKey = PGPSecretKey(
            PGPKeyPair(publicKey, pgpPrivateKey),
            newKeyPair,
            sha1Calc,
            signatureSubpacketVector,
            null,
            contentSignerBuilder,
            secretKeyEncryptor,
        )

        val newPublicKeyRing = PGPPublicKeyRing.insertPublicKey(publicKeyRing, newSubKey.publicKey)
        val newSecretKeyRing = PGPSecretKeyRing.insertSecretKey(secretKeyRing, newSubKey)

        val newPublicKeyFilePath = keyPair.publicKey.path
        val armoredPublicKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPublicKeyFilePath)))
        newPublicKeyRing.encode(armoredPublicKeyOutputStream)
        armoredPublicKeyOutputStream.close()

        // Save the updated private key
        val newPrivateKeyFilePath = keyPair.secretKey!!.path
        val armoredPrivateKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPrivateKeyFilePath)))
        newSecretKeyRing.encode(armoredPrivateKeyOutputStream)
        armoredPrivateKeyOutputStream.close()
    }

    fun removeSubkey(
        keyPair: PgpKeyPair,
        passphrase: String,
        subkeyId: String,
    ) {
        val secretKeyRing = getSecretKeyRing(keyPair.secretKey!!.path, passphrase)
        val publicKeyRing = getPublicKeyRing(keyPair.publicKey.path)

        val newPublicKeyRing = PGPPublicKeyRing(publicKeyRing.publicKeys.asSequence().filterNot {
            it.keyID.toString() == subkeyId
        }.toList())

        val newSecretKeyRing = PGPSecretKeyRing(secretKeyRing.secretKeys.asSequence().filterNot {
            it.keyID.toString() == subkeyId
        }.toList())

        // Save the updated public key
        val newPublicKeyFilePath = keyPair.publicKey.path
        val armoredPublicKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPublicKeyFilePath)))
        newPublicKeyRing.encode(armoredPublicKeyOutputStream)
        armoredPublicKeyOutputStream.close()

        // Save the updated private key
        val newPrivateKeyFilePath = keyPair.secretKey!!.path
        val armoredPrivateKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPrivateKeyFilePath)))
        newSecretKeyRing.encode(armoredPrivateKeyOutputStream)
        armoredPrivateKeyOutputStream.close()
    }

    fun revokeSubkey(
        keyPair: PgpKeyPair,
        passphrase: String,
        subkeyId: String,
    ) {
        val secretKeyRing = getSecretKeyRing(keyPair.secretKey!!.path, passphrase)
        val publicKeyRing = getPublicKeyRing(keyPair.publicKey.path)

        val secretKey = secretKeyRing.secretKey
        val publicKey = publicKeyRing.publicKey

        val subKeys = secretKeyRing.publicKeys.asSequence().toList().filter { !it.isMasterKey }
        val subKey = subKeys.find { it.keyID.toString() == subkeyId }


        val pgpPrivateKey = secretKey!!.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC").build(passphrase.toCharArray())
        )

        val signerBuilder = BcPGPContentSignerBuilder(publicKey.algorithm, HashAlgorithmTags.SHA256)
        val signatureGenerator = PGPSignatureGenerator(signerBuilder, publicKey)
        val subHashedPacketsGen = PGPSignatureSubpacketGenerator()

        subHashedPacketsGen.setRevocationReason(true, RevocationReasonTags.NO_REASON, "")
        subHashedPacketsGen.setSignatureCreationTime(true, Date())
        signatureGenerator.setHashedSubpackets(subHashedPacketsGen.generate())

        signatureGenerator.init(PGPSignature.SUBKEY_REVOCATION, pgpPrivateKey)
        val signature = signatureGenerator.generateCertification(publicKey, subKey)
        val newPublicKey = PGPPublicKey.addCertification(subKey, signature)

        updateKeyRingsWithNewKey(
            newPublicKey = newPublicKey,
            secretKey = secretKeyRing.getSecretKey(newPublicKey.keyID),
            publicKeyRing = publicKeyRing,
            secretKeyRing = secretKeyRing,
            publicKeyPath = keyPair.publicKey.path,
            secretKeyPath = keyPair.secretKey!!.path,
        )
    }

    fun changePassword(
        keyPair: PgpKeyPair,
        oldPassword: String,
        newPassword: String,
    ) {
        val secretKeyRing = getSecretKeyRing(keyPair.secretKey!!.path, oldPassword)

        val updatedKeys = mutableListOf<PGPSecretKey>()

        for (secretKey in secretKeyRing.secretKeys) {
            val oldKeyDecryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(oldPassword.toCharArray())
            val newPbe = PgpKeys.createSecretKeyEncryptor(newPassword.toCharArray())

            val newSecretKey = PGPSecretKey.copyWithNewPassword(
                secretKey,
                oldKeyDecryptor,
                newPbe,
            )
            updatedKeys.add(newSecretKey)
        }

        val updatedSecretKeyRing = PGPSecretKeyRing(updatedKeys)
        val newPrivateKeyFilePath = keyPair.secretKey!!.path
        val armoredPrivateKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPrivateKeyFilePath)))
        updatedSecretKeyRing.encode(armoredPrivateKeyOutputStream)
        armoredPrivateKeyOutputStream.close()
    }

    private fun updateKeyRingsWithNewKey(
        newPublicKey: PGPPublicKey,
        secretKey: PGPSecretKey,
        publicKeyRing: PGPPublicKeyRing,
        secretKeyRing: PGPSecretKeyRing,
        publicKeyPath: String,
        secretKeyPath: String,
    ) {
        val newPublicKeyRing = PGPPublicKeyRing(publicKeyRing.publicKeys.asSequence().map {
            if (it.keyID == newPublicKey.keyID) newPublicKey else it
        }.toList())

        val newSecretKey = PGPSecretKey.replacePublicKey(secretKey, newPublicKey)
        val newSecretKeyRing = PGPSecretKeyRing(secretKeyRing.secretKeys.asSequence().map {
            if (it.keyID == newSecretKey.keyID) newSecretKey else it
        }.toList())

        val newPublicKeyFilePath = publicKeyPath
        val armoredPublicKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPublicKeyFilePath)))
        newPublicKeyRing.encode(armoredPublicKeyOutputStream)
        armoredPublicKeyOutputStream.close()

        val newPrivateKeyFilePath = secretKeyPath
        val armoredPrivateKeyOutputStream = ArmoredOutputStream(FileOutputStream(File(newPrivateKeyFilePath)))
        newSecretKeyRing.encode(armoredPrivateKeyOutputStream)
        armoredPrivateKeyOutputStream.close()
    }
}
