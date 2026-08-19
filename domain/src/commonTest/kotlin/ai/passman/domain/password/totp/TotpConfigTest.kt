package ai.passman.domain.password.totp

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TotpConfigTest {
    @Test
    fun `a raw base32 seed gets the RFC defaults`() {
        val config = TotpConfig.parse("JBSWY3DPEHPK3PXP")
        assertContentEquals(Base32.decode("JBSWY3DPEHPK3PXP"), config.secret)
        assertEquals(6, config.digits)
        assertEquals(30, config.periodSeconds)
    }

    @Test
    fun `a raw seed is cleaned like the setup pages show it`() {
        val config = TotpConfig.parse(" jbsw y3dp ehpk 3pxp ")
        assertContentEquals(Base32.decode("JBSWY3DPEHPK3PXP"), config.secret)
    }

    @Test
    fun `an otpauth uri carries its own parameters`() {
        val config = TotpConfig.parse(
            "otpauth://totp/Example:mia@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=8&period=60&algorithm=SHA1",
        )
        assertContentEquals(Base32.decode("JBSWY3DPEHPK3PXP"), config.secret)
        assertEquals(8, config.digits)
        assertEquals(60, config.periodSeconds)
    }

    @Test
    fun `uri parameters are optional`() {
        val config = TotpConfig.parse("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
        assertEquals(6, config.digits)
        assertEquals(30, config.periodSeconds)
    }

    @Test
    fun `a real-world uri with a percent-encoded label parses`() {
        // Captured from a live camera scan: label and issuer carry %20, the label carries a colon.
        // Neither field feeds code generation, so no percent-decoding is needed or done.
        val config = TotpConfig.parse(
            "otpauth://totp/ACME%20Co:jdoe@example.com?secret=AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG" +
                "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        )
        assertContentEquals(Base32.decode("AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG"), config.secret)
        assertEquals(6, config.digits)
        assertEquals(30, config.periodSeconds)
    }

    @Test
    fun `normalizing a default-parameter uri keeps just the secret`() {
        assertEquals(
            "AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG",
            TotpConfig.normalizeSeed(
                "otpauth://totp/ACME%20Co:jdoe@example.com?secret=AUSJD7LZ5H27TAC7NW2IJMATDMVDUPUG" +
                    "&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
            ),
        )
    }

    @Test
    fun `normalizing keeps the full uri when it carries non-default parameters`() {
        val uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=8"
        assertEquals(uri, TotpConfig.normalizeSeed(uri))
    }

    @Test
    fun `normalizing a raw seed trims it`() {
        assertEquals("JBSWY3DPEHPK3PXP", TotpConfig.normalizeSeed(" JBSWY3DPEHPK3PXP "))
    }

    @Test
    fun `normalizing an invalid seed yields null`() {
        assertEquals(null, TotpConfig.normalizeSeed("not base32 !!"))
        assertEquals(null, TotpConfig.normalizeSeed("otpauth://totp/Example?issuer=NoSecret"))
    }

    @Test
    fun `hotp uris are rejected`() {
        assertFailsWith<IllegalArgumentException> {
            TotpConfig.parse("otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP&counter=0")
        }
    }

    @Test
    fun `unsupported algorithms are rejected with a clear message`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            TotpConfig.parse("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256")
        }
        assertEquals(true, failure.message?.contains("SHA256"))
    }

    @Test
    fun `a uri without a secret is rejected`() {
        assertFailsWith<IllegalArgumentException> { TotpConfig.parse("otpauth://totp/Example?issuer=Example") }
    }

    @Test
    fun `blank input is rejected`() {
        assertFailsWith<IllegalArgumentException> { TotpConfig.parse("   ") }
    }

    @Test
    fun `out of range digits are rejected`() {
        assertFailsWith<IllegalArgumentException> {
            TotpConfig.parse("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=4")
        }
    }
}
