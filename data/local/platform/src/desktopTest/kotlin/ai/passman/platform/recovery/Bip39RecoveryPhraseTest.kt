package ai.passman.platform.recovery

import ai.passman.platform.crypto.SecureRandomService
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Bip39RecoveryPhraseTest {
    @Test
    fun `encodes 256 bits as the standard 24-word BIP39 phrase`() {
        val phrase = Bip39RecoveryPhrase.fromEntropy(ByteArray(32))

        assertEquals(
            List(23) { "abandon" }.plus("art").joinToString(" "),
            phrase,
        )
            assertTrue(Bip39RecoveryPhrase.isValid(phrase))
        }

    @Test
    fun `generates exactly 24 valid English words from 256 random bits`() {
        val phrase = Bip39RecoveryPhrase.generate(
            object : SecureRandomService {
                override fun nextBytes(size: Int): ByteArray {
                    assertEquals(32, size)
                    return ByteArray(size) { it.toByte() }
                }
            },
        )

        assertEquals(24, phrase.split(' ').size)
        assertTrue(Bip39RecoveryPhrase.isValid(phrase))
    }
}
