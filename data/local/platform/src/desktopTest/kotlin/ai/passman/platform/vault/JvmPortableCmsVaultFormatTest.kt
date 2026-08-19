package ai.passman.platform.vault

import ai.passman.crypto.vault.PasswordVaultCipher
import ai.passman.platform.crypto.JvmSecureRandomService
import ai.passman.platform.recovery.JvmPortableVaultRecovery
import ai.passman.repo.Platform
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class JvmPortableCmsVaultFormatTest {
    private val root = Files.createTempDirectory("portable-cms-test").toFile()

    @AfterTest
    fun tearDown() {
        root.deleteRecursively()
    }

    @Test
    fun sealsAndOpensSignedEncryptedJson() {
        val session = PasswordVaultCipher().createSession("login-password").sessionKey
        try {
            val format = JvmPortableCmsVaultFormat(JvmPortableVaultRecovery(platform(root), JvmSecureRandomService()))
            val plaintext = "[{\"entryName\":\"example\"}]".encodeToByteArray()

            val ciphertext = format.seal("work", plaintext, session)

            assertTrue(format.isPortable(ciphertext))
            assertContentEquals(plaintext, format.open("work", ciphertext, session))
            ciphertext[ciphertext.lastIndex] = (ciphertext.last() + 1).toByte()
            assertFails { format.open("work", ciphertext, session) }
        } finally {
            session.destroy()
        }
    }

    private fun platform(root: File) = object : Platform() {
        override fun getLocalPath(): String = root.absolutePath
    }
}
