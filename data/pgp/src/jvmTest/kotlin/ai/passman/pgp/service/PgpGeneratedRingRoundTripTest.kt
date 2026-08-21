package ai.passman.pgp.service

import ai.passman.domain.base.model.Outcome
import ai.passman.keys.model.RSA
import ai.passman.pgp.BaseTest
import ai.passman.pgp.utils.PgpKeys
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
            val otherPrivateKeyPath = writeKeyRingPair(otherKeyDirectory, "other", password).secretPath

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

        private class KeyRingPaths(val secretPath: String, val publicPath: String)

        /**
         * The ring these tests run against, built the way the app builds one: the Create Key screen
         * goes straight to [PgpKeys.createPgpKeyRingGenerator], so that is what "app-generated"
         * means here. RSA-4096 to match what the screen defaults to.
         */
        private fun writeKeyRingPair(directory: File, userId: String, password: String): KeyRingPaths {
            val generator = PgpKeys.createPgpKeyRingGenerator(
                userId = userId,
                algorithm = RSA,
                length = 4096,
                expirationInSeconds = 0,
                password = password,
            )
            val userDirectory = File(directory, userId).apply { mkdirs() }
            val secret = File(userDirectory, "secret.asc")
            val public = File(userDirectory, "public.asc")
            PgpKeys.saveSecretKeyRingToFile(generator.generateSecretKeyRing(), secret.absolutePath)
            PgpKeys.savePublicKeyRingToFile(generator.generatePublicKeyRing(), public.absolutePath)
            return KeyRingPaths(secretPath = secret.absolutePath, publicPath = public.absolutePath)
        }

        @JvmStatic
        @BeforeClass
        fun createKeyRing() {
            keyDirectory = Files.createTempDirectory("pgp-generated-key-ring").toFile()
            val paths = writeKeyRingPair(keyDirectory, userId, password)
            privateKeyPath = paths.secretPath
            publicKeyPath = paths.publicPath
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
