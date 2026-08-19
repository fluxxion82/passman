package ai.passman.pgp.service

import ai.passman.pgp.BaseTest
import ai.passman.pgp.utils.PgpKeys
import ai.passman.keys.model.EDDSA
import ai.passman.domain.base.model.Outcome
import java.io.File
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.junit.Test

class PgpClientTest : BaseTest() {
    private val pgpService: PgpClient = PgpClient()

    /** Armored public + secret ring written to a temp dir. Generated per test — never committed. */
    private class KeyRingFiles(val publicPath: String, val secretPath: String)

    private fun generateKeyRingFiles(userId: String, password: String): KeyRingFiles {
        val generator = PgpKeys.createPgpKeyRingGenerator(
            userId = userId,
            algorithm = EDDSA,
            length = 256,
            expirationInSeconds = 0,
            password = password,
        )
        val directory = Files.createTempDirectory("pgp_client_test").toFile()
        directory.deleteOnExit()
        val secret = File(directory, "secret.asc").apply { deleteOnExit() }
        val public = File(directory, "public.asc").apply { deleteOnExit() }
        PgpKeys.saveSecretKeyRingToFile(generator.generateSecretKeyRing(), secret.absolutePath)
        PgpKeys.savePublicKeyRingToFile(generator.generatePublicKeyRing(), public.absolutePath)
        return KeyRingFiles(publicPath = public.absolutePath, secretPath = secret.absolutePath)
    }

    @Test
    fun `getSecretKeyRing accepts a binary unarmored ring file`() = runTest {
        // Imports copy files verbatim, so a secret ring on disk is not guaranteed to be armored.
        val generator = PgpKeys.createPgpKeyRingGenerator(
            userId = "Binary Test <bin@example.com>",
            algorithm = EDDSA,
            length = 256,
            expirationInSeconds = 0,
            password = "binary-password",
        )
        val ring = generator.generateSecretKeyRing()
        val file = File.createTempFile("binary_secret_ring", ".gpg")
        try {
            file.outputStream().use { ring.encode(it) }

            val parsed = pgpService.getSecretKeyRing(file.absolutePath, "binary-password")

            assertEquals(ring.secretKey.keyID, parsed.secretKey.keyID)
        } finally {
            file.delete()
        }
    }

    @Test
    fun `test encrypt and decrypt`() = runTest {
        val original = "hello, it's mr ed"

        val keys = generateKeyRingFiles("Encrypt Test <encrypt@example.com>", "encrypt-password")
        val publicKey = keys.publicPath

        when (val outcomeSign = pgpService.encryptPgpMessage(original, publicKey)) {
            is Outcome.Success -> {
                val signed = outcomeSign.value
                println("encrypt:")
                println(signed)

                val privateKey = keys.secretPath

                val verified = pgpService.decryptPgpMessage(signed, privateKey, "encrypt-password")
                println("decrypt: $verified")
                assertTrue(verified is Outcome.Success)
                // assertEquals(original, verified)
            }

            is Outcome.Error -> assertTrue(false, outcomeSign.message)
        }
    }

    @Test
    fun `test clear sign and verify`() = runTest {
        val original = "hello, it's mr ed"

        val keys = generateKeyRingFiles("Clear Sign Test <clearsign@example.com>", "clearsign-password")
        val filepath = keys.secretPath

        when (val outcomeSign = pgpService.clearSign(original, filepath, "clearsign-password")) {
            is Outcome.Success -> {
                val signed = outcomeSign.value
                println("signed:")
                println(signed)

                val pubFilepath = keys.publicPath

                val verified = pgpService.verifyClearSignature(signed, pubFilepath)
                println("verified: $verified")
                assertTrue(verified is Outcome.Success)
            }

            is Outcome.Error -> assertTrue(false, "Failed to clear sign: ${outcomeSign.message}")
        }
    }

    @Test
    fun `test sign encrypt and verify decrypt`() = runTest {
        val original = "hello, it's mr ed"

        val privateFile = File("src/jvmTest/resources/private.asc")
        val privateFilepath = privateFile.absolutePath

        val publicFile = File("src/jvmTest/resources/public.asc")
        val publicFilePath = publicFile.absolutePath

        when (val outcomeSign = pgpService.signAndEncrypt(original, publicFilePath, privateFilepath, "password")) {
            is Outcome.Success -> {
                val signed = outcomeSign.value
                println("signed:")
                println(signed)

                val verified = pgpService.verifyAndDecrypt(signed, privateFilepath, "password", publicFilePath)
                println("verified: $verified")
                assertTrue(verified is Outcome.Success)
            }

            is Outcome.Error -> assertTrue(false, "Failed to clear sign")
        }
    }

    @Test
    fun `test sign`() = runTest {
        val original = "hello, it's mr ed"

        val privateFile = File("src/jvmTest/resources/private.asc")
        val privateFilepath = privateFile.absolutePath

        when (val outcomeSign = pgpService.sign(original, privateFilepath, "password", true, "SHA256")) {
            is Outcome.Success -> {
                val signed = outcomeSign.value
                println("signed:")
                println(signed)

                val publicFile = File("src/jvmTest/resources/public.asc")
                val publicFilepath = publicFile.absolutePath

                val verified = pgpService.verifySignature(signed, publicFilepath)

                println("verified: $verified")
                assertTrue(verified is Outcome.Success)
            }

            is Outcome.Error -> assertTrue(false, "Failed to clear sign")
        }
    }
}
