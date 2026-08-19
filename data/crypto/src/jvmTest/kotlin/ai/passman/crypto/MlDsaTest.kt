package ai.passman.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MlDsaTest {
    @Test
    fun signsAndVerifies() {
        val keyPair = MlDsa.generateKeyPair()
        val message = "sender-authenticated sync payload".encodeToByteArray()

        val signature = MlDsa.sign(message, keyPair.privateSeed)

        assertEquals(1_952, keyPair.publicKey.size)
        assertEquals(32, keyPair.privateSeed.size)
        assertEquals(3_309, signature.size)
        assertTrue(MlDsa.verify(message, signature, keyPair.publicKey))
    }

    @Test
    fun rejectsSignatureFromWrongKey() {
        val signer = MlDsa.generateKeyPair()
        val other = MlDsa.generateKeyPair()
        val message = "sender-authenticated sync payload".encodeToByteArray()

        assertFalse(MlDsa.verify(message, MlDsa.sign(message, signer.privateSeed), other.publicKey))
    }

    @Test
    fun seedReconstructionDerivesTheSamePublicKey() {
        val keyPair = MlDsa.generateKeyPair()

        val reconstructed = MlDsa.publicKeyOf(keyPair.privateSeed)

        assertContentEquals(keyPair.publicKey, reconstructed)
    }
}
