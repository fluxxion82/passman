package ai.passman.pgp

import ai.passman.keys.model.RSA
import ai.passman.pgp.service.PgpClient
import ai.passman.pgp.utils.PgpKeys
import ai.passman.domain.base.model.Outcome
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Before

class PGPKeysTest {
    private lateinit var pgpService: PgpClient

    @Before
    fun setUp() {
        pgpService = PgpClient()
    }

    @Test
    fun `test create key pair`() = runTest(StandardTestDispatcher()) {
        val original = "hello, it's mr ed"
        val secretKeyRingGenerator = PgpKeys.createPgpKeyRingGenerator("Test <test@user.com>", RSA, 4096, 0,"password")
        val secretKeyRing = secretKeyRingGenerator.generateSecretKeyRing()
        val secretKey = PgpKeys.getSecretSignKeyFromRing(secretKeyRing)
        val publicKey = PgpKeys.getPublicEncryptKeyFromRing(secretKeyRing)

        val publicKeyFile = File("src/jvmTest/resources/publicKey.asc").apply { writeBytes(publicKey!!.encoded) }

        when (val outcomeSign = pgpService.encryptPgpMessage(original, publicKeyFile.absolutePath)) {
            is Outcome.Success -> {
                val encrypted = outcomeSign.value
                assertTrue {
                    encrypted.startsWith("-----BEGIN PGP MESSAGE-----")
                }

                val privateKeyFile = File("src/jvmTest/resources/privateKey.asc").apply {
                    writeBytes(secretKey!!.encoded)
                }

                val verified = pgpService.decryptPgpMessage(encrypted, privateKeyFile.absolutePath, "password")
                assertTrue {
                    verified is Outcome.Success && original == verified.value
                }

                privateKeyFile.delete()
            }

            is Outcome.Error -> assertTrue(false, outcomeSign.message)
        }

        publicKeyFile.delete()
    }
}
