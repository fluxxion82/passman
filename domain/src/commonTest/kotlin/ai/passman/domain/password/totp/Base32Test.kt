package ai.passman.domain.password.totp

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class Base32Test {
    private fun decodeToText(encoded: String) = Base32.decode(encoded).decodeToString()

    @Test
    fun `decodes the RFC 4648 vectors`() {
        assertContentEquals(ByteArray(0), Base32.decode(""))
        assertContentEquals("f".encodeToByteArray(), Base32.decode("MY======"))
        assertContentEquals("fo".encodeToByteArray(), Base32.decode("MZXQ===="))
        assertContentEquals("foo".encodeToByteArray(), Base32.decode("MZXW6==="))
        assertContentEquals("foob".encodeToByteArray(), Base32.decode("MZXW6YQ="))
        assertContentEquals("fooba".encodeToByteArray(), Base32.decode("MZXW6YTB"))
        assertContentEquals("foobar".encodeToByteArray(), Base32.decode("MZXW6YTBOI======"))
    }

    @Test
    fun `padding is optional`() {
        assertContentEquals("foobar".encodeToByteArray(), Base32.decode("MZXW6YTBOI"))
    }

    @Test
    fun `lowercase and interior whitespace are tolerated`() {
        // Authenticator setup pages show secrets lowercase in groups of four.
        assertContentEquals("foobar".encodeToByteArray(), Base32.decode("mzxw 6ytb oi"))
    }

    @Test
    fun `the reference authenticator test seed decodes`() {
        assertContentEquals(
            byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte()),
            Base32.decode("JBSWY3DPEHPK3PXP"),
        )
    }

    @Test
    fun `invalid characters are rejected`() {
        assertFailsWith<IllegalArgumentException> { Base32.decode("MZXW1===") } // 1 is not in the alphabet
        assertFailsWith<IllegalArgumentException> { Base32.decode("MZXW8===") }
    }
}
