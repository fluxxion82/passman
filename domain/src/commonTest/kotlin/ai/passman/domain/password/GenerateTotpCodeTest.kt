package ai.passman.domain.password

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class GenerateTotpCodeTest {
    // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ is base32 for the RFC 6238 test secret "12345678901234567890".
    private val rfcSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test
    fun `generates the RFC vector for the frozen clock`() = runTest {
        val generate = GenerateTotpCode(epochSeconds = { 59L })
        val result = generate("otpauth://totp/Example?secret=$rfcSeed&digits=8")
        assertEquals("94287082", result?.code)
        assertEquals(1, result?.secondsRemaining)
        assertEquals(30, result?.periodSeconds)
    }

    @Test
    fun `a raw seed uses six digits`() = runTest {
        val generate = GenerateTotpCode(epochSeconds = { 59L })
        assertEquals("287082", generate(rfcSeed)?.code)
    }

    @Test
    fun `an invalid seed yields null instead of throwing`() = runTest {
        val generate = GenerateTotpCode(epochSeconds = { 59L })
        assertNull(generate("not base32 !!"))
        assertNull(generate(""))
    }
}
