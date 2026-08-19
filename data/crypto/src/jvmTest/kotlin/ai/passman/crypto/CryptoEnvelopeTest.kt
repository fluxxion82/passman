package ai.passman.crypto

import java.security.KeyPairGenerator
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CryptoEnvelopeTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val pub = keyPair.public
    private val priv = keyPair.private

    @Test
    fun v2_roundTrips() {
        val plain = "the vault contents — αβγ 🔐".encodeToByteArray()
        val decrypted = CryptoEnvelope.decrypt(CryptoEnvelope.encrypt(plain, pub), priv)
        assertContentEquals(plain, decrypted)
    }

    @Test
    fun emptyPlaintext_roundTrips() {
        val decrypted = CryptoEnvelope.decrypt(CryptoEnvelope.encrypt(ByteArray(0), pub), priv)
        assertContentEquals(ByteArray(0), decrypted)
    }

    @Test
    fun v2_isNonDeterministic() {
        val plain = "same input".encodeToByteArray()
        val a = CryptoEnvelope.encrypt(plain, pub)
        val b = CryptoEnvelope.encrypt(plain, pub)
        assertFalse(a.contentEquals(b), "random DEK + nonce must make ciphertexts differ")
        // ...but both decrypt back to the same plaintext.
        assertContentEquals(plain, CryptoEnvelope.decrypt(a, priv))
        assertContentEquals(plain, CryptoEnvelope.decrypt(b, priv))
    }

    @Test
    fun v2_hasMagicVersionSuiteHeader() {
        val env = CryptoEnvelope.encrypt("x".encodeToByteArray(), pub)
        assertEquals(0x50.toByte(), env[0]) // 'P'
        assertEquals(0x4D.toByte(), env[1]) // 'M'
        assertEquals(0x4E.toByte(), env[2]) // 'N'
        assertEquals(0x56.toByte(), env[3]) // 'V'
        assertEquals(1.toByte(), env[4], "version")
        assertEquals(2.toByte(), env[5], "suite = OAEP+GCM")
    }

    @Test
    fun tamperedCiphertext_failsAuthentication() {
        val env = CryptoEnvelope.encrypt("secret".encodeToByteArray(), pub)
        env[env.size - 1] = (env[env.size - 1].toInt() xor 0x01).toByte() // flip a tag/ct byte
        // Not `assertFails`: it catches Throwable, so an OutOfMemoryError would read as a pass.
        assertFailsWith<AEADBadTagException> { CryptoEnvelope.decrypt(env, priv) }
    }

    @Test
    fun tamperedHeaderNonce_failsAuthentication() {
        val env = CryptoEnvelope.encrypt("secret".encodeToByteArray(), pub)
        // The nonce lives just before the ciphertext; flipping it must break the AAD binding.
        val nonceByte = env.size - 16 - 6 // roughly inside nonce region (ct tag=16, nonce=12)
        env[nonceByte] = (env[nonceByte].toInt() xor 0x01).toByte()
        assertFailsWith<AEADBadTagException> { CryptoEnvelope.decrypt(env, priv) }
    }

    @Test
    fun wrongKey_failsToDecrypt() {
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val env = CryptoEnvelope.encrypt("secret".encodeToByteArray(), pub)
        // The wrong RSA key fails the OAEP unwrap before AES-GCM ever runs; AEADBadTagException is a
        // subclass, so this also holds if a provider surfaces the failure at the tag instead.
        assertFailsWith<BadPaddingException> { CryptoEnvelope.decrypt(env, other.private) }
    }

    @Test
    fun legacyV1Blob_stillDecrypts() {
        val plain = "old vault written before the envelope".encodeToByteArray()
        val v1 = CryptoEnvelope.encryptLegacyV1ForTest(plain, pub)
        assertFalse(
            v1[0] == 0x50.toByte() && v1[1] == 0x4D.toByte(),
            "legacy blob must NOT carry the v2 magic (it's JSON)",
        )
        assertContentEquals(plain, CryptoEnvelope.decrypt(v1, priv))
    }

    @Test
    fun writesAreAlwaysV2_evenForShortInput() {
        val env = CryptoEnvelope.encrypt(ByteArray(0), pub)
        assertTrue(env.size > 8, "even empty plaintext yields a full v2 header + tag")
        assertEquals(0x50.toByte(), env[0])
    }
}
