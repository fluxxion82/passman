package ai.passman.domain.connectivity

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The proof primitives both halves of the QR ceremony share, exercised away from either half. */
class PairingProofTest {
    @Test
    fun `constant time comparison answers on content and never on length alone`() {
        assertTrue(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        assertTrue(constantTimeEquals(ByteArray(0), ByteArray(0)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        assertFalse(constantTimeEquals(byteArrayOf(0), byteArrayOf(0, 0)))
        assertFalse(constantTimeEquals(byteArrayOf(1, 2, 3), ByteArray(0)))
    }

    @Test
    fun `the proof codec is url-safe and unpadded, because the wire format is frozen`() {
        // Bytes chosen so the standard alphabet would spell '+' and '/', and so the length would
        // otherwise be padded: a codec change on either end of the ceremony shows up here rather
        // than as proofs that silently never verify.
        val bytes = byteArrayOf(0xFB.toByte(), 0xEF.toByte(), 0xFF.toByte(), 0x01)

        val encoded = PROOF_BASE64.encode(bytes)

        assertEquals("--__AQ", encoded)
        assertContentEquals(bytes, PROOF_BASE64.decode(encoded))
    }
}
