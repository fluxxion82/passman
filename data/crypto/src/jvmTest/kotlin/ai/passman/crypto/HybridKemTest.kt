package ai.passman.crypto

import javax.crypto.AEADBadTagException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class HybridKemTest {
    private val kp = HybridKem.generateKeyPair()

    @Test
    fun roundTrips() {
        val plain = "quantum-resistant vault — αβγ 🔐".encodeToByteArray()
        val env = HybridKem.encrypt(plain, kp.publicKey)
        assertContentEquals(plain, HybridKem.decrypt(env, kp.privateKey))
    }

    @Test
    fun emptyPlaintextRoundTrips() {
        val env = HybridKem.encrypt(ByteArray(0), kp.publicKey)
        assertContentEquals(ByteArray(0), HybridKem.decrypt(env, kp.privateKey))
    }

    @Test
    fun keySizesAreMlKem768() {
        assertEquals(32, kp.publicKey.x25519.size, "X25519 public key")
        assertEquals(1184, kp.publicKey.mlkem.size, "ML-KEM-768 public key")
        assertEquals(32, kp.privateKey.x25519.size, "X25519 private key")
    }

    @Test
    fun envelopeHasMagicVersionHybridSuite() {
        val env = HybridKem.encrypt("x".encodeToByteArray(), kp.publicKey)
        assertEquals(0x50.toByte(), env[0]) // 'P'
        assertEquals(0x4D.toByte(), env[1]) // 'M'
        assertEquals(0x4E.toByte(), env[2]) // 'N'
        assertEquals(0x56.toByte(), env[3]) // 'V'
        assertEquals(1.toByte(), env[4], "version")
        assertEquals(3.toByte(), env[5], "suite = hybrid")
    }

    @Test
    fun isNonDeterministic() {
        val plain = "same".encodeToByteArray()
        val a = HybridKem.encrypt(plain, kp.publicKey)
        val b = HybridKem.encrypt(plain, kp.publicKey)
        assertFalse(a.contentEquals(b), "fresh ephemeral X25519 + ML-KEM encapsulation per call")
        assertContentEquals(plain, HybridKem.decrypt(a, kp.privateKey))
        assertContentEquals(plain, HybridKem.decrypt(b, kp.privateKey))
    }

    @Test
    fun tamperedCiphertextFails() {
        val env = HybridKem.encrypt("secret".encodeToByteArray(), kp.publicKey)
        env[env.size - 1] = (env[env.size - 1].toInt() xor 0x01).toByte()
        // Not `assertFails`: it catches Throwable, so an OutOfMemoryError would read as a pass.
        assertFailsWith<AEADBadTagException> { HybridKem.decrypt(env, kp.privateKey) }
    }

    @Test
    fun tamperedEphemeralKeyFails() {
        val env = HybridKem.encrypt("secret".encodeToByteArray(), kp.publicKey)
        env[6] = (env[6].toInt() xor 0x01).toByte() // first byte of ephemeral X25519 pubkey
        // The header is bound as AAD and the tampered key changes the derived DEK, so either way the
        // failure surfaces at the GCM tag.
        assertFailsWith<AEADBadTagException> { HybridKem.decrypt(env, kp.privateKey) }
    }

    @Test
    fun wrongRecipientKeyFails() {
        val other = HybridKem.generateKeyPair()
        val env = HybridKem.encrypt("secret".encodeToByteArray(), kp.publicKey)
        // Wrong X25519 AND wrong ML-KEM secret -> derived key differs -> GCM tag fails.
        assertFailsWith<AEADBadTagException> { HybridKem.decrypt(env, other.privateKey) }
    }

    @Test
    fun downgradeSuiteByteRejected() {
        val env = HybridKem.encrypt("secret".encodeToByteArray(), kp.publicKey)
        env[5] = 2 // pretend it's the classical suite
        // Rejected structurally, before any key agreement runs — not by the (also-broken) AAD.
        assertFailsWith<IllegalArgumentException> { HybridKem.decrypt(env, kp.privateKey) }
    }
}
