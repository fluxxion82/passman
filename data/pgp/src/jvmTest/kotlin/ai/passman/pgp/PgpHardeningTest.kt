package ai.passman.pgp

import ai.passman.keys.model.EDDSA
import ai.passman.keys.model.RSA
import ai.passman.pgp.service.PgpClient
import ai.passman.pgp.utils.PgpHelper
import ai.passman.pgp.utils.PgpKeys
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyType
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPEncryptedData
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder

class PgpHardeningTest {
    @Test
    fun `Ed25519 key ring uses legacy EdDSA and ECDH packets and roundtrips`() {
        val generator = PgpKeys.createPgpKeyRingGenerator(
            "Test <test@example.com>",
            EDDSA,
            256,
            0,
            "password",
        )
        val secretRing = generator.generateSecretKeyRing()
        val publicRing = generator.generatePublicKeyRing()
        val keys = secretRing.publicKeys.asSequence().toList()
        val primaryKey = keys.single { it.isMasterKey }
        val encryptionSubkey = keys.single { !it.isMasterKey }

        assertEquals(4, primaryKey.version)
        assertEquals(PublicKeyAlgorithmTags.EDDSA_LEGACY, primaryKey.algorithm)
        assertEquals(
            KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA,
            primaryKey.signatures.asSequence().first().hashedSubPackets.keyFlags,
        )
        assertEquals(4, encryptionSubkey.version)
        assertEquals(PublicKeyAlgorithmTags.ECDH, encryptionSubkey.algorithm)
        assertEquals(
            KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE,
            encryptionSubkey.signatures.asSequence().first().hashedSubPackets.keyFlags,
        )

        val plaintext = "Ed25519 key ring".encodeToByteArray()
        val plainFile = Files.createTempFile("pgp-ed25519", ".txt").toFile().apply { writeBytes(plaintext) }
        val publicKeyFile = Files.createTempFile("pgp-ed25519", ".asc").toFile().apply {
            writeArmored(this, publicRing.encoded)
        }
        try {
            val encrypted = ByteArrayOutputStream()
            PgpHelper.encryptFile(encrypted, plainFile, encryptionSubkey, armor = false, withIntegrityCheck = true)

            val decrypted = ByteArrayOutputStream()
            PgpHelper.decryptFile(ByteArrayInputStream(encrypted.toByteArray()), decrypted, secretRing, "password")
            assertEquals(String(plaintext), decrypted.toString())

            val signed = PgpHelper.sign(plaintext, secretRing.secretKey, "password", armor = false, digestName = "SHA512")
            assertTrue(PgpHelper.verifySignature(signed, publicKeyFile.absolutePath))
        } finally {
            plainFile.delete()
            publicKeyFile.delete()
        }
    }

    @Test
    fun `plain encryption writes AES-256 integrity-protected packet and roundtrips`() {
        val (secretRing, _) = generateKeyRings()
        val encryptionKey = requireNotNull(PgpKeys.getPublicEncryptKeyFromRing(secretRing))
        val plaintext = "plain encryption hardening".encodeToByteArray()
        val plainFile = Files.createTempFile("pgp-hardening", ".txt").toFile().apply { writeBytes(plaintext) }
        val encrypted = ByteArrayOutputStream()

        try {
            PgpHelper.encryptFile(encrypted, plainFile, encryptionKey, armor = false, withIntegrityCheck = true)

            val encryptedData = encryptedData(encrypted.toByteArray())
            val privateKey = requireNotNull(PgpKeys.findSecretKey(secretRing, encryptedData.keyID, "password"))
            val decryptor = JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(PgpHelper.BOUNCY_PROVIDER)
                .build(privateKey)

            assertEquals(PGPEncryptedData.AES_256, encryptedData.getSymmetricAlgorithm(decryptor))
            assertTrue(encryptedData.isIntegrityProtected)

            val decrypted = ByteArrayOutputStream()
            PgpHelper.decryptFile(ByteArrayInputStream(encrypted.toByteArray()), decrypted, secretRing, "password")
            assertEquals(String(plaintext), decrypted.toString())
        } finally {
            plainFile.delete()
        }
    }

    @Test
    fun `adding a subkey encrypts its secret packet with AES-256`() {
        val (secretRing, publicRing) = generateKeyRings()
        val keyFiles = writeKeyFiles(secretRing, publicRing)

        try {
            PgpClient().addSubKey(
                keyPair = keyFiles.keyPair,
                passphrase = "password",
                algorithm = "RSA",
                length = 2048,
                keyFlags = KeyFlags.ENCRYPT_COMMS,
                expirationTimeInSeconds = 0,
            )

            val updated = PgpKeys.loadSecretKeyRing(keyFiles.secretFile.absolutePath)
            assertEquals(PGPEncryptedData.AES_256, updated.secretKeys.asSequence().last().keyEncryptionAlgorithm)
        } finally {
            keyFiles.directory.deleteRecursively()
        }
    }

    @Test
    fun `changing a password re-encrypts secret packets with AES-256`() {
        val (secretRing, publicRing) = generateKeyRings()
        val keyFiles = writeKeyFiles(secretRing, publicRing)

        try {
            PgpClient().changePassword(keyFiles.keyPair, "password", "new-password")

            val updated = PgpKeys.loadSecretKeyRing(keyFiles.secretFile.absolutePath)
            updated.secretKeys.forEach { secretKey ->
                assertEquals(PGPEncryptedData.AES_256, secretKey.keyEncryptionAlgorithm)
            }
        } finally {
            keyFiles.directory.deleteRecursively()
        }
    }

    private fun encryptedData(data: ByteArray): PGPPublicKeyEncryptedData {
        val factory = PGPObjectFactory(ByteArrayInputStream(data), BcKeyFingerprintCalculator())
        return (factory.nextObject() as PGPEncryptedDataList).encryptedDataObjects.next() as PGPPublicKeyEncryptedData
    }

    private fun generateKeyRings(): Pair<PGPSecretKeyRing, org.bouncycastle.openpgp.PGPPublicKeyRing> {
        val generator = PgpKeys.createPgpKeyRingGenerator("Test <test@example.com>", RSA, 2048, 0, "password")
        return generator.generateSecretKeyRing() to generator.generatePublicKeyRing()
    }

    private fun writeKeyFiles(
        secretRing: PGPSecretKeyRing,
        publicRing: org.bouncycastle.openpgp.PGPPublicKeyRing,
    ): KeyFiles {
        val directory = Files.createTempDirectory("pgp-hardening").toFile()
        val secretFile = File(directory, "secret.asc")
        val publicFile = File(directory, "public.asc")
        writeArmored(secretFile, secretRing.encoded)
        writeArmored(publicFile, publicRing.encoded)
        val placeholder = PgpKey(
            fileName = "key.asc",
            path = publicFile.absolutePath,
            type = PgpKeyType.Public,
            keyId = 0,
            creationTime = 0,
            expirationTime = null,
            isRevoked = false,
            algorithm = "RSA",
            bitStrength = 2048,
            userIds = emptyList(),
            fingerprint = "",
            isMaster = true,
            isSigningKey = true,
            isEncryptionKey = true,
        )
        return KeyFiles(
            directory,
            secretFile,
            PgpKeyPair(placeholder, placeholder.copy(path = secretFile.absolutePath, type = PgpKeyType.Secret)),
        )
    }

    private fun writeArmored(file: File, encoded: ByteArray) {
        ArmoredOutputStream(FileOutputStream(file)).use { it.write(encoded) }
    }

    private data class KeyFiles(val directory: File, val secretFile: File, val keyPair: PgpKeyPair)
}
