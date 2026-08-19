package ai.passman.keystore

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import java.io.File
import java.nio.file.Files
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(ExperimentalEncodingApi::class)
class JvmKeyStoreClientHardeningTest {
    private val client = JvmKeyStoreClient()

    @Test
    fun `encryptData roundtrips new format with RSA key`() {
        val keys = KeyService.createRSAKeys()

        val encrypted = requireSuccess(client.encryptData(keys.public, "RSA envelope", "rsa-aad".encodeToByteArray()))

        val payload = Base64.decode(encrypted.ciphertextOrPath)
        assertTrue(payload.copyOfRange(0, 4).contentEquals("PMKS".encodeToByteArray()))
        val decrypted = requireSuccess(client.decryptData(keys.private, encrypted.ciphertextOrPath, "rsa-aad"))
        assertEquals("RSA envelope", decrypted)
    }

    @Test
    fun `encryptData roundtrips new format with AES key`() {
        val key = KeyService.createAESKey()

        val encrypted = requireSuccess(client.encryptData(key, "AES envelope", "aes-aad".encodeToByteArray()))

        val decrypted = requireSuccess(client.decryptData(key, encrypted.ciphertextOrPath, "aes-aad"))
        assertEquals("AES envelope", decrypted)
    }

    @Test
    fun `decryptData rejects tampered new-format ciphertext`() {
        val key = KeyService.createAESKey()
        val encrypted = requireSuccess(client.encryptData(key, "tamper me", "aad".encodeToByteArray()))
        val tampered = Base64.decode(encrypted.ciphertextOrPath).also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }

        assertIs<Outcome.Error>(client.decryptData(key, Base64.encode(tampered), "aad"))
    }

    @Test
    fun `decryptData reads legacy bare-cipher blob`() {
        val key = KeyService.createAESKey()
        val plaintext = "legacy ciphertext"
        val legacy = Cipher.getInstance(key.algorithm, "BC").apply {
            init(Cipher.ENCRYPT_MODE, key)
        }.doFinal(plaintext.encodeToByteArray())

        val decrypted = requireSuccess(client.decryptData(key, Base64.encode(legacy), ""))
        assertEquals(plaintext, decrypted)
    }

    /**
     * The identity key must survive a password change.
     *
     * It did not. `changeKeystorePassword` called `KeyStore.load(null, oldPassword)` on the store it
     * had just read, which is the API's way of initialising an *empty* keystore: every entry was
     * discarded before the copy loop ran, the file was replaced with an empty PKCS#12, and the method
     * returned `Outcome.Success`. The account's only RSA identity was gone with no error anywhere.
     */
    @Test
    fun `changeKeystorePassword preserves the key entry under the new password`() {
        val dir = Files.createTempDirectory("keystore-rekey").toFile()
        try {
            val keystore = client.createKeyStore(KeyStoreType.PKCS12, dir.absolutePath, "a.pfx", "old-pw").getOrThrow()
            client.addKeystoreKey(keystore, "passmanMain", "old-pw", KeystoreKeyAlgorithm.RSA).getOrThrow()
            val originalKey = client.unwrapKey(
                client.getKeyStoreInfo(keystore).getOrThrow(),
                "passmanMain",
                "old-pw".toCharArray(),
            )
            assertNotNull(originalKey)

            val outcome = client.changeKeystorePassword(dir.absolutePath, "a.pfx", KeyStoreType.PKCS12, "old-pw", "new-pw")

            assertIs<Outcome.Success<Unit>>(outcome)
            val reloaded = client.getKeyStoreInfo(keystore.copy(password = "new-pw")).getOrThrow()
            assertEquals(
                listOf("passmanmain"),
                reloaded.aliases().toList(),
                "the re-keyed store must still hold the identity key",
            )
            assertContentEquals(
                originalKey.encoded,
                client.unwrapKey(reloaded, "passmanMain", "new-pw".toCharArray())?.encoded,
                "the re-keyed store must hold the SAME private key, not a fresh one",
            )
            assertNull(
                client.getKeyStoreInfo(keystore.copy(password = "old-pw")).getOrNull(),
                "the old password must no longer open the store",
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    /** A failed re-key must leave the original file openable, not a half-written replacement. */
    @Test
    fun `changeKeystorePassword with the wrong old password leaves the store untouched`() {
        val dir = Files.createTempDirectory("keystore-rekey-fail").toFile()
        try {
            val keystore = client.createKeyStore(KeyStoreType.PKCS12, dir.absolutePath, "a.pfx", "old-pw").getOrThrow()
            client.addKeystoreKey(keystore, "passmanMain", "old-pw", KeystoreKeyAlgorithm.RSA).getOrThrow()
            val before = File(dir, "a.pfx").readBytes()

            val outcome = client.changeKeystorePassword(dir.absolutePath, "a.pfx", KeyStoreType.PKCS12, "wrong-pw", "new-pw")

            assertIs<Outcome.Error>(outcome)
            assertContentEquals(before, File(dir, "a.pfx").readBytes(), "the .pfx must be byte-identical")
            assertNotNull(
                client.unwrapKey(client.getKeyStoreInfo(keystore).getOrThrow(), "passmanMain", "old-pw".toCharArray()),
            )
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun <T : Any> requireSuccess(outcome: Outcome<T>): T = when (outcome) {
        is Outcome.Success -> outcome.value
        is Outcome.Error -> error(outcome.message)
    }
}
