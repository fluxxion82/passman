package ai.passman.pgp.service

import ai.passman.pgp.BaseTest
import ai.passman.pgp.TestContextFacade
import ai.passman.pgp.utils.PgpHelper
import ai.passman.pgp.utils.PgpKeys
import ai.passman.pgp.utils.RSAKeyPairGenerator
import ai.passman.domain.base.CoroutinesContextFacade
import java.io.*
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPPublicKey
import org.junit.Before
import org.junit.Test

class PgpTest : BaseTest() {
    private lateinit var coroutinesContextFacade: CoroutinesContextFacade

    @Before
    fun setUp() {
        coroutinesContextFacade = TestContextFacade()
    }

    @Test
    fun testEncrypt() = runTest {
        val plainText = File("src/jvmTest/resources/plaintext.txt").apply {
            writeText("hello text encrypt.\n")
        }
        val cryptedText = ByteArrayOutputStream()

        val pubKeyIn = File("src/jvmTest/resources/pgpTestPublicKey.asc")

        val pubKey = PgpKeys.readPublicKey(pubKeyIn.absolutePath)
        pubKey.let { PgpHelper.encryptFile(cryptedText, plainText, it, armor = true, withIntegrityCheck = true) }
        val encrypted = cryptedText.toString()

        println("encrypted:")
        println(encrypted)

        assertTrue {
            encrypted.startsWith("-----BEGIN PGP MESSAGE-----")
        }
    }

    @Test
    fun decrypt() {
        val plainText = ByteArrayOutputStream()
        val cryptedText = ByteArrayInputStream(encryptedMessageConst.toByteArray())

        PgpHelper.decryptFile(
            cryptedText,
            plainText,
            PgpKeys.loadSecretKeyRing("src/jvmTest/resources/pgpTestPrivateKey.asc"),
            "password"
        )

        println("decrypted:")
        println(plainText.toString())

        assertTrue {
            plainText.toString().startsWith("hello text encrypt.")
        }
    }

    @Test
    fun testSignEncryptAndVerifyDecrypt() {
        val plainText = File("src/jvmTest/resources/plaintext.txt").apply {
            writeText("hello text to sign and encrypt.\n")
        }

        val pubKeyIn = File("src/jvmTest/resources/pgpTestPublicKey.asc")
        val priKeyIn = File("src/jvmTest/resources/pgpTestPrivateKey.asc")

        val privateKey = PgpKeys.readSecretKey(priKeyIn.absolutePath)
        val publicKey = PgpKeys.readPublicKey(pubKeyIn.absolutePath)

        val signed = PgpHelper.signAndEncrypt(plainText.readBytes(), privateKey, "password", publicKey, true)

        println("signed:")
        println(signed.decodeToString())

        val secretRing = PgpKeys.loadSecretKeyRing(priKeyIn.absolutePath)
        val orig = PgpHelper.decryptAndVerify(signed, secretRing, "password", pubKeyIn.absolutePath)
        println("signed orig:")
        println(orig.decodeToString())

        assertContentEquals(plainText.readBytes(), orig)
    }

    @Test
    fun testClearSignAndVerify() {
        val plainText = File("src/jvmTest/resources/plaintext.txt").apply {
            writeText("hello text to clear sign.\n")
        }

        val pubKeyIn = File("src/jvmTest/resources/pgpTestPublicKey.asc")
        val priKeyIn = File("src/jvmTest/resources/pgpTestPrivateKey.asc")

        val privateKey = PgpKeys.readSecretKey(priKeyIn.absolutePath)

        val signed = PgpHelper.clearSign(plainText.readBytes(), privateKey, "password".toCharArray(), "SHA512")

        println("signed:")
        println(signed.decodeToString())

        val verified = PgpHelper.verifyClearSign(signed, pubKeyIn.absolutePath)
        println("verified: $verified")
        assertTrue(verified)
    }

    @Test
    fun testSignAndVerify() {
        val plainText = File("src/jvmTest/resources/plaintext.txt").apply {
            writeText("hello text to sign.\n")
        }

        val pubKeyIn = File("src/jvmTest/resources/public.asc")
        val priKeyIn = File("src/jvmTest/resources/private.asc")

        val privateKey = PgpKeys.readSecretKey(priKeyIn.absolutePath)

        // val signed = pgpHelper.createDetachedSignature(privKey, "password".toCharArray(), plainText.readBytes())
        val signed = PgpHelper.sign(plainText.readBytes(), privateKey, "password", true)
        println("signed:")
        println(String(signed))

        val verified = PgpHelper.verifySignature(signed, pubKeyIn.absolutePath)
        println("verified: $verified")
        assertTrue(verified)
    }

    @Test
    fun testGenerateKeys() {
        val rkpg = RSAKeyPairGenerator()

        Security.addProvider(BouncyCastleProvider())

        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(1024)

        val kp: KeyPair = kpg.generateKeyPair()
        val out1 = FileOutputStream("src/jvmTest/resources/gen_private.asc")
        val out2 = FileOutputStream("src/jvmTest/resources/gen_public.asc")

        rkpg.exportKeyPair(out1, out2, kp.public, kp.private, "sterling", "password".toCharArray(), true)

        var contentBuilder = StringBuilder()
        var fin = FileInputStream("src/jvmTest/resources/gen_public.asc")
        BufferedReader(InputStreamReader(fin)).use { br ->
            var line: String?
            while (br.readLine().also { line = it } != null) {
                contentBuilder.append(line).append("\n")
            }
        }
        println("pub:")
        println(contentBuilder.toString())
        File("src/jvmTest/resources/gen_public.asc").deleteOnExit()

        contentBuilder = StringBuilder()
        fin = FileInputStream("src/jvmTest/resources/gen_private.asc")
        BufferedReader(InputStreamReader(fin)).use { br ->
            var line: String?
            while (br.readLine().also { line = it } != null) {
                contentBuilder.append(line).append("\n")
            }
        }
        println("secret:")
        println(contentBuilder.toString())
        File("src/jvmTest/resources/gen_private.asc").deleteOnExit()
    }

    fun exportAscii(pgpKey: PGPPublicKey): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { os -> pgpKey.encode(os) }
        return out.toString()
    }

    fun ByteArray.toHex(): String = joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }

    companion object {
        val encryptedMessageConst = """
            |-----BEGIN PGP MESSAGE-----
            |Version: BCPG v1.75.0

            |wcFMA5IvMxbRUUmQAQ/+OeSTg1e0kM86PDI94Ko4cw8UDolsLieOk7fuKSg4LYqG
            |t2fOLXetwlmLL4b705iEWZlsvo9bbnxiYNysb0hLbagPfgWplGMkb6d+Wd8OyhU1
            |D+kZ44jMpVcxK7rAFaklPSfZ6SpN9ZF1eZrmbc4ByG4AD14M3vzrB1DvFolWYRMs
            |EEc6bTOgvMwKSWnFSEI1MzWw3Y320PI/2G/fQ57cJcJlJ3AuOQgpvJ+4pgPl9oN8
            |BUOreFlX+tN62LmeCtdKihFr2Qutte059cKIVtS5veS6LXJE0jOPJKZI4yLEGdmR
            |R60UZbhyjWB3PW22eLQS9/SVu8/Gpaonzd7/52VqSHR08WQwUdH+8fLMRyy0dTKI
            |rk1igsReD+FNVQlKyOUyI7cMiABbDgaor564yCc1bXXzM/qQNhw4yxWaAbzn65OT
            |oIcohe59nGScDgb7pDnwVdHESSdAvmbDUw919zi/gDjbWLcKsdWcBSoltf9DFg+W
            |vZ8u78tcFoSLd0CgOO5kQ5m3DK5aADYxwiLt+AMfyonhN+Ez9ctIXNmqfmMfO+WK
            |dri4yUIZm0ngsgZlvu4IEo338W8H5yjuRdqTbBriK5Wes4+0SCWbVY137F2qpCS2
            |MfpkXRatYzJXhzHQjPgtgdkli8oWjkd/P7R4L7I9ITOda8EtJDBevZN6WtLpMnvS
            |TAENgHivRwUK1zwvekVYEwAF9ecsOjn9C8FNd8Wf0s7C1qcfvN97+sI0z4oibVCv
            |MnvoCKUgGCvnhP0bSNULIiTPQLbC1nviNIsBkhU=
            |=QRjc
            |-----END PGP MESSAGE-----
        """.trimMargin()

        val myEncryptedMessageConst = """
            |-----BEGIN PGP MESSAGE-----
            |Version: BCPG v1.75.0

            |wcFMAzrYVycfPgl2ARAAhQIP3bH/VStMQMS+ATOGzWiCAj4wvOvuCowMbr9efovu
            |xpEhlPRbq7hlXc/Nhl/XIRL+jTVYARPDsZI6koysguFdCL8jtBI8GRdklLsHENvU
            |SWgCQwLHwIeU8m7aj+eypYicwYV0XE5x3AMvk4CJ71EC5H+bV+iDsApvT6S4bX7t
            |h+vkAg0qIG8oumfhxOiEtOqMegCOIIGtDuaJhoX4YWVtXsV+80YCi6IiLXhRFyNH
            |o47l30TXRHRshiPnNu6WISiAmM+Xn9bXR/kXzzNPEyMCoh4ao0q3BmMPYc74VYrm
            |A7lF/W0FimKY8sNXQ5JduOZzjguyV7xtL8HLuk5TqoX+a7EwGi9zpAIE7rH1Mkt/
            |h/E1S1BhspyeFd0Szqb18ZtaiMy/qGEfubgg7tX0BfU2hgQD3tEo0fJbey/pgnKU
            |KF+FeWNkLzZdu0glcyYr0wWyquO/sLDqDfVB6P2+VN22ZjyppO7hm6GPKz1f7MCq
            |mVpxAuIoOnjEYMoGGn+Fm/UaYNNfUTPLWTBiE50lspQRpDC2Wv7pT37WmSjcdZa4
            |YoICQMHdPkZjuaXr/HyWIaCgF59qjAdgOG4o0Uu7u4a1yEL3QfPNv0XDSjrxVqAo
            |0L+jJjZ+0PrtNnxYbS3ZsfFHcIVSheI75XhG92+x5HTQihIGNK1BIXlm601ydPzS
            |TAHqTx4URtJ/TIRznEAYb5rozsJ9Dbml+ypJXyKUP/mMbM75D06VSDO+ydhO+uVz
            |ruDo75mjl+6BMEIgAzWLLfWkLqyVxvsFN+DTwyo=
            |=JdH9
            |-----END PGP MESSAGE-----
        """.trimMargin()
    }
}
