package ai.passman.domain.password.totp

import kotlin.test.Test
import kotlin.test.assertEquals

class TotpGeneratorTest {
    private val rfcSecret = "12345678901234567890".encodeToByteArray()

    @Test
    fun `RFC 4226 appendix D HOTP vectors`() {
        val expected = listOf(
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        )
        expected.forEachIndexed { counter, code ->
            assertEquals(code, TotpGenerator.hotp(rfcSecret, counter.toLong(), digits = 6))
        }
    }

    @Test
    fun `RFC 6238 appendix B TOTP vectors`() {
        val vectors = mapOf(
            59L to "94287082",
            1111111109L to "07081804",
            1111111111L to "14050471",
            1234567890L to "89005924",
            2000000000L to "69279037",
            20000000000L to "65353130",
        )
        vectors.forEach { (epochSeconds, code) ->
            assertEquals(
                code,
                TotpGenerator.code(rfcSecret, epochSeconds, periodSeconds = 30, digits = 8),
                "at t=$epochSeconds",
            )
        }
    }

    @Test
    fun `codes keep their leading zeros`() {
        // 1111111109 -> 07081804 above already proves it at 8 digits; pin the 6-digit slice too.
        assertEquals("081804", TotpGenerator.code(rfcSecret, 1111111109L, periodSeconds = 30, digits = 6))
    }

    @Test
    fun `seconds remaining count down within the period`() {
        assertEquals(30, TotpGenerator.secondsRemaining(60L, periodSeconds = 30))
        assertEquals(1, TotpGenerator.secondsRemaining(59L, periodSeconds = 30))
        assertEquals(15, TotpGenerator.secondsRemaining(75L, periodSeconds = 30))
    }
}
