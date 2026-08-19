package ai.passman.domain.connectivity.model

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private typealias Reason = PairingQrPayload.ParseResult.Reason

@OptIn(ExperimentalEncodingApi::class)
class PairingQrPayloadTest {
    @Test
    fun `encode and parse round trip preserves host port digest and nonce`() {
        val payload = payload(host = "192.0.2.10", port = 2324)

        val parsed = parsed(payload.encode())

        assertEquals("192.0.2.10", parsed.host)
        assertEquals(2324, parsed.port)
        assertContentEquals(digest, parsed.digest)
        assertContentEquals(nonce, parsed.nonce)
    }

    @Test
    fun `encode matches the frozen wire format`() {
        val wire = payload().encode()

        assertEquals(
            "passman-pair:v1?host=192.0.2.10&port=2324" +
                "&digest=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" +
                "&nonce=__79_Pv6-fj39vX08_Lx8O_u7ezr6uno5-bl5OPi4eA",
            wire,
        )
        val parsed = parsed(wire)
        assertEquals("192.0.2.10", parsed.host)
        assertEquals(2324, parsed.port)
        assertContentEquals(digest, parsed.digest)
        assertContentEquals(nonce, parsed.nonce)
    }

    @Test
    fun `text from other schemes is not a pairing code`() {
        assertIs<PairingQrPayload.ParseResult.NotPairingCode>(
            PairingQrPayload.parse("otpauth://totp/x"),
        )
        assertIs<PairingQrPayload.ParseResult.NotPairingCode>(PairingQrPayload.parse("hello"))
        assertIs<PairingQrPayload.ParseResult.NotPairingCode>(PairingQrPayload.parse(""))
    }

    @Test
    fun `only our scheme looks like a pairing code`() {
        assertTrue(PairingQrPayload.looksLikePairingCode(payload().encode()))
        assertTrue(PairingQrPayload.looksLikePairingCode("  PASSMAN-PAIR:v9?nonsense  "))
        assertFalse(PairingQrPayload.looksLikePairingCode("otpauth://totp/x"))
        assertFalse(PairingQrPayload.looksLikePairingCode(""))
    }

    @Test
    fun `a pairing code missing parameters is incomplete`() {
        assertEquals(Reason.INCOMPLETE, reasonFor("passman-pair:v1?host=1.2.3.4"))
        assertEquals(
            Reason.INCOMPLETE,
            reasonFor("passman-pair:v1?port=2324&digest=${base64.encode(digest)}&nonce=${base64.encode(nonce)}"),
        )
    }

    @Test
    fun `a pairing code with no query at all is incomplete`() {
        assertEquals(Reason.INCOMPLETE, reasonFor("passman-pair:v1"))
    }

    @Test
    fun `a pairing code with no version is incomplete rather than unsupported`() {
        assertEquals(Reason.INCOMPLETE, reasonFor("passman-pair:"))
        assertEquals(Reason.INCOMPLETE, reasonFor("passman-pair:?x=y"))
    }

    @Test
    fun `a pairing code version this app does not know is unsupported`() {
        val v2 = payload().encode().replaceFirst("passman-pair:v1", "passman-pair:v2")

        assertEquals(Reason.UNSUPPORTED_VERSION, reasonFor(v2))
    }

    @Test
    fun `scheme version and parameter names are case insensitive`() {
        val shouted = "PassMan-Pair:V1?HOST=192.0.2.10&Port=2324" +
            "&Digest=${base64.encode(digest)}&NONCE=${base64.encode(nonce)}"

        val parsed = parsed(shouted)

        assertEquals("192.0.2.10", parsed.host)
        assertEquals(2324, parsed.port)
        assertContentEquals(digest, parsed.digest)
        assertContentEquals(nonce, parsed.nonce)
    }

    @Test
    fun `a digest or nonce that is not 32 bytes is invalid`() {
        val shortDigest = "passman-pair:v1?host=192.0.2.10&port=2324" +
            "&digest=${base64.encode(ByteArray(31) { 0x11 })}&nonce=${base64.encode(nonce)}"
        val longNonce = "passman-pair:v1?host=192.0.2.10&port=2324" +
            "&digest=${base64.encode(digest)}&nonce=${base64.encode(ByteArray(33) { 0x22 })}"

        assertEquals(Reason.INVALID, reasonFor(shortDigest))
        assertEquals(Reason.INVALID, reasonFor(longNonce))
    }

    @Test
    fun `padded base64 parameters are refused`() {
        val padded = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT)
        val paddedDigest = "passman-pair:v1?host=192.0.2.10&port=2324" +
            "&digest=${padded.encode(digest)}&nonce=${base64.encode(nonce)}"

        assertTrue(padded.encode(digest).endsWith("="))
        assertEquals(Reason.INVALID, reasonFor(paddedDigest))
    }

    @Test
    fun `a port that is not canonical decimal is invalid`() {
        for (port in listOf("+2324", "0002324", "0", "-1", "2324 ", "2_324", "65536", "abc")) {
            val code = "passman-pair:v1?host=192.0.2.10&port=$port" +
                "&digest=${base64.encode(digest)}&nonce=${base64.encode(nonce)}"
            assertEquals(Reason.INVALID, reasonFor(code), port)
        }
    }

    @Test
    fun `a repeated parameter is invalid`() {
        val duplicated = payload().encode() + "&host=evil.example"

        assertEquals(Reason.INVALID, reasonFor(duplicated))
    }

    @Test
    fun `unknown parameters are tolerated for forward compatibility`() {
        val fromANewerDevice = payload().encode() + "&relay=wss%3A%2F%2Fexample&flags=7"

        assertEquals("192.0.2.10", parsed(fromANewerDevice).host)
    }

    @Test
    fun `hostnames and IPv6 addresses survive a round trip`() {
        for (host in listOf("desk.local", "fe80::1c2d:3e4f:5a6b:7c8d", "[fe80::1]", "my-desktop")) {
            assertEquals(host, parsed(payload(host = host).encode()).host)
        }
    }

    @Test
    fun `hosts carrying parameter delimiters or whitespace are refused`() {
        val hosts = listOf(
            "1.2.3.4&port=1", "a=b", "1.2.3.4?x", "1.2 3.4", "u@1.2.3.4", "1.2.3.4/p", "a#b", "a%2F", "",
        )
        for (host in hosts) {
            assertFailsWith<IllegalArgumentException>(message = host) { payload(host = host) }
        }
    }

    @Test
    fun `the payload copies the arrays it is handed and the arrays it hands back`() {
        val callersDigest = digest.copyOf()
        val callersNonce = nonce.copyOf()
        val payload = PairingQrPayload("192.0.2.10", 2324, callersDigest, callersNonce)

        callersDigest[0] = 0x7F
        callersNonce[0] = 0x7F
        payload.digest[1] = 0x7F
        payload.nonce[1] = 0x7F

        assertContentEquals(digest, payload.digest)
        assertContentEquals(nonce, payload.nonce)
    }

    @Test
    fun `payloads are equal when their contents are`() {
        val left = payload()
        val right = PairingQrPayload("192.0.2.10", 2324, digest.copyOf(), nonce.copyOf())

        assertEquals(left, right)
        assertEquals(left.hashCode(), right.hashCode())

        val otherNonce = nonce.copyOf().also { it[7] = (it[7] + 1).toByte() }
        assertNotEquals(left, PairingQrPayload("192.0.2.10", 2324, digest, otherNonce))
        assertNotEquals(left, payload(host = "desk.local"))
        assertNotEquals(left, payload(port = 2325))
    }

    private val digest = ByteArray(32) { it.toByte() }
    private val nonce = ByteArray(32) { (0xFF - it).toByte() }
    private val base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

    private fun payload(host: String = "192.0.2.10", port: Int = 2324): PairingQrPayload =
        PairingQrPayload(host = host, port = port, digest = digest, nonce = nonce)

    private fun parsed(text: String): PairingQrPayload =
        assertIs<PairingQrPayload.ParseResult.Parsed>(PairingQrPayload.parse(text)).payload

    private fun reasonFor(text: String): Reason =
        assertIs<PairingQrPayload.ParseResult.Malformed>(PairingQrPayload.parse(text)).reason
}
