package ai.passman.pgp.service

import ai.passman.domain.base.model.Outcome
import ai.passman.pgp.BaseTest
import java.io.File
import java.nio.file.Files
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.AfterClass
import org.junit.BeforeClass
import org.junit.Test

class PgpGeneratedRingRoundTripTest : BaseTest() {
    private val client = PgpClient()

    @Test
    fun `sign encrypt then verify decrypt round trip with app-generated key ring`() = runTest {
        val original = "hello from an app-generated PGP key ring"

        when (val encrypted = client.signAndEncrypt(original, publicKeyPath, privateKeyPath, password)) {
            is Outcome.Success -> {
                when (val decrypted = client.verifyAndDecrypt(encrypted.value, privateKeyPath, password, publicKeyPath)) {
                    is Outcome.Success -> assertTrue(decrypted.value.contains(original))
                    is Outcome.Error -> assertTrue(false, decrypted.message)
                }
            }

            is Outcome.Error -> assertTrue(false, encrypted.message)
        }
    }

    @Test
    fun `encrypt message then decrypt message round trip with app-generated key ring`() = runTest {
        val original = "encrypted message from an app-generated PGP key ring"

        when (val encrypted = client.encryptPgpMessage(original, publicKeyPath)) {
            is Outcome.Success -> {
                when (val decrypted = client.decryptPgpMessage(encrypted.value, privateKeyPath, password)) {
                    is Outcome.Success -> assertTrue(decrypted.value.contains(original))
                    is Outcome.Error -> assertTrue(false, decrypted.message)
                }
            }

            is Outcome.Error -> assertTrue(false, encrypted.message)
        }
    }

    @Test
    fun `clear sign then verify clear signature with app-generated key ring`() = runTest {
        val original = "clear signed message from an app-generated PGP key ring"

        when (val signed = client.clearSign(original, privateKeyPath, password)) {
            is Outcome.Success -> {
                when (val verified = client.verifyClearSignature(signed.value, publicKeyPath)) {
                    is Outcome.Success -> assertTrue(verified.value == Unit)
                    is Outcome.Error -> assertTrue(false, verified.message)
                }
            }

            is Outcome.Error -> assertTrue(false, signed.message)
        }
    }

    @Test
    fun `sign then verify signature with app-generated key ring`() = runTest {
        val original = "signed message from an app-generated PGP key ring"

        when (val signed = client.sign(original, privateKeyPath, password, armor = true, digestName = "SHA256")) {
            is Outcome.Success -> {
                when (val verified = client.verifySignature(signed.value, publicKeyPath)) {
                    is Outcome.Success -> assertTrue(verified.value == Unit)
                    is Outcome.Error -> assertTrue(false, verified.message)
                }
            }

            is Outcome.Error -> assertTrue(false, signed.message)
        }
    }

    @Test
    fun `encrypt file then decrypt file round trip with app-generated key ring`() = runTest {
        val original = "encrypted file from an app-generated PGP key ring"
        val plainFile = File(keyDirectory, "encrypt-file-plain.txt").apply { writeText(original) }
        val encryptedFile = File(keyDirectory, "encrypt-file-encrypted.asc")
        val decryptedFile = File(keyDirectory, "encrypt-file-decrypted.txt")

        when (val encrypted = client.encryptPgpFile(plainFile.absolutePath, encryptedFile.absolutePath, publicKeyPath)) {
            is Outcome.Success -> {
                when (val decrypted = client.decryptPgpFile(encrypted.value, decryptedFile.absolutePath, privateKeyPath, password)) {
                    is Outcome.Success -> assertTrue(File(decrypted.value).readText().contains(original))
                    is Outcome.Error -> assertTrue(false, decrypted.message)
                }
            }

            is Outcome.Error -> assertTrue(false, encrypted.message)
        }
    }

    @Test
    fun `clear sign file then verify clear signature file with app-generated key ring`() = runTest {
        val original = "clear signed file from an app-generated PGP key ring"
        val plainFile = File(keyDirectory, "clear-sign-file-plain.txt").apply { writeText(original) }
        val signedFile = File(keyDirectory, "clear-sign-file-signed.asc")

        when (val signed = client.clearSignFile(plainFile.absolutePath, signedFile.absolutePath, privateKeyPath, password)) {
            is Outcome.Success -> {
                when (val verified = client.verifyClearSignatureFile(signed.value, publicKeyPath)) {
                    is Outcome.Success -> assertTrue(verified.value == Unit)
                    is Outcome.Error -> assertTrue(false, verified.message)
                }
            }

            is Outcome.Error -> assertTrue(false, signed.message)
        }
    }

    @Test
    fun `sign encrypt file then verify decrypt file round trip with app-generated key ring`() = runTest {
        val original = "signed encrypted file from an app-generated PGP key ring"
        val plainFile = File(keyDirectory, "sign-encrypt-file-plain.txt").apply { writeText(original) }
        val encryptedFile = File(keyDirectory, "sign-encrypt-file-encrypted.asc")
        val decryptedFile = File(keyDirectory, "sign-encrypt-file-decrypted.txt")

        when (val encrypted = client.signAndEncryptFile(
            plainFile.absolutePath,
            encryptedFile.absolutePath,
            publicKeyPath,
            privateKeyPath,
            password,
        )) {
            is Outcome.Success -> {
                when (val decrypted = client.verifyAndDecryptFile(
                    encrypted.value,
                    decryptedFile,
                    privateKeyPath,
                    password,
                    publicKeyPath,
                )) {
                    is Outcome.Success -> assertTrue(File(decrypted.value).readText().contains(original))
                    is Outcome.Error -> assertTrue(false, decrypted.message)
                }
            }

            is Outcome.Error -> assertTrue(false, encrypted.message)
        }
    }

    @Test
    fun `verify decrypt with wrong password fails for app-generated key ring`() = runTest {
        val original = "wrong password should not decrypt"

        when (val encrypted = client.signAndEncrypt(original, publicKeyPath, privateKeyPath, password)) {
            is Outcome.Success -> {
                when (val decrypted = client.verifyAndDecrypt(encrypted.value, privateKeyPath, "wrong-password", publicKeyPath)) {
                    is Outcome.Success -> assertTrue(false, "Expected decryption with a wrong password to fail")
                    is Outcome.Error -> assertTrue(decrypted.message.isNotEmpty())
                }
            }

            is Outcome.Error -> assertTrue(false, encrypted.message)
        }
    }

    @Test
    fun `verify decrypt with non recipient secret key fails for app-generated key ring`() = runTest {
        val original = "non recipient key should not decrypt"
        val otherKeyDirectory = Files.createTempDirectory("pgp-other-generated-key-ring").toFile()

        try {
            client.createKeyRings(
                userId = "other",
                password = password,
                keyDirectory = otherKeyDirectory.absolutePath,
                secretKeyRingFilename = "secret.asc",
                publicKeyRingFilename = "public.asc",
            ).getOrThrow()
            val otherPrivateKeyPath = File(otherKeyDirectory, "other/secret.asc").absolutePath

            when (val encrypted = client.signAndEncrypt(original, publicKeyPath, privateKeyPath, password)) {
                is Outcome.Success -> {
                    when (val decrypted = client.verifyAndDecrypt(encrypted.value, otherPrivateKeyPath, password, publicKeyPath)) {
                        is Outcome.Success -> assertTrue(false, "Expected decryption with a non-recipient key to fail")
                        is Outcome.Error -> assertTrue(decrypted.message.isNotEmpty())
                    }
                }

                is Outcome.Error -> assertTrue(false, encrypted.message)
            }
        } finally {
            otherKeyDirectory.deleteRecursively()
        }
    }

    @Test
    fun `decrypt message with garbage input fails for app-generated key ring`() = runTest {
        when (val decrypted = client.decryptPgpMessage("not an encrypted PGP message", privateKeyPath, password)) {
            is Outcome.Success -> assertTrue(false, "Expected garbage input to fail decryption")
            is Outcome.Error -> assertTrue(decrypted.message.isNotEmpty())
        }
    }

    companion object {
        private const val userId = "tester"
        private const val password = "password123"
        private lateinit var keyDirectory: File
        private lateinit var privateKeyPath: String
        private lateinit var publicKeyPath: String

        @JvmStatic
        @BeforeClass
        fun createKeyRing() {
            keyDirectory = Files.createTempDirectory("pgp-generated-key-ring").toFile()
            PgpClient().createKeyRings(
                userId = userId,
                password = password,
                keyDirectory = keyDirectory.absolutePath,
                secretKeyRingFilename = "secret.asc",
                publicKeyRingFilename = "public.asc",
            ).getOrThrow()
            privateKeyPath = File(keyDirectory, "$userId/secret.asc").absolutePath
            publicKeyPath = File(keyDirectory, "$userId/public.asc").absolutePath
        }

        @JvmStatic
        @AfterClass
        fun deleteKeyRing() {
            if (::keyDirectory.isInitialized) {
                keyDirectory.deleteRecursively()
            }
        }
    }
}
