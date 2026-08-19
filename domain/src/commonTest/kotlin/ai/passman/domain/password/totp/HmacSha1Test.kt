package ai.passman.domain.password.totp

import kotlin.test.Test
import kotlin.test.assertEquals

class HmacSha1Test {
    @OptIn(ExperimentalStdlibApi::class)
    private fun hmacHex(key: ByteArray, message: ByteArray) = HmacSha1.compute(key, message).toHexString()

    @Test
    fun `RFC 2202 test case 1`() {
        assertEquals(
            "b617318655057264e28bc0b6fb378c8ef146be00",
            hmacHex(ByteArray(20) { 0x0b }, "Hi There".encodeToByteArray()),
        )
    }

    @Test
    fun `RFC 2202 test case 2`() {
        assertEquals(
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            hmacHex("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray()),
        )
    }

    @Test
    fun `RFC 2202 test case 3 fifty repeated bytes`() {
        assertEquals(
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            hmacHex(ByteArray(20) { 0xaa.toByte() }, ByteArray(50) { 0xdd.toByte() }),
        )
    }

    @Test
    fun `key longer than the block size is hashed first`() {
        // RFC 2202 test case 6: 80-byte key forces the key-reduction path.
        assertEquals(
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            hmacHex(ByteArray(80) { 0xaa.toByte() }, "Test Using Larger Than Block-Size Key - Hash Key First".encodeToByteArray()),
        )
    }
}
