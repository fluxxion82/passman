package ai.passman.design.pass

import ai.passman.domain.connectivity.model.PairingQrPayload
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The pairing QR is the one surface where an encoding mistake is invisible in code review and
 * only shows up as "the other phone won't scan it". These tests decode what the composable would
 * actually draw, so a wrong colour, a dropped quiet zone or a cropped matrix fails here instead
 * of in someone's hands.
 */
class QrPixelsTest {

    private fun payload(host: String = "192.0.2.10") = PairingQrPayload(
        host = host,
        port = PairingQrPayload.DEFAULT_PAIRING_PORT,
        digest = ByteArray(32) { it.toByte() },
        // Deliberately not sequential: base64url encodes 0x3E/0x3F as '-' and '_', which push the
        // string out of QR alphanumeric mode into byte mode. That is the real payload's shape.
        nonce = ByteArray(32) { (255 - it).toByte() },
    )

    private fun decode(pixels: QrPixels): String =
        MultiFormatReader().decode(
            BinaryBitmap(HybridBinarizer(RGBLuminanceSource(pixels.width, pixels.height, pixels.argb))),
            mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(com.google.zxing.BarcodeFormat.QR_CODE)),
        ).text

    @Test
    fun `raster is square and at least the requested size`() {
        val pixels = requireNotNull(pairingQrPixels(payload().encode()))

        assertEquals(pixels.width, pixels.height, "QR raster must be square")
        assertTrue(pixels.width >= QR_PIXELS, "expected at least $QR_PIXELS px, was ${pixels.width}")
        assertEquals(pixels.width * pixels.height, pixels.argb.size)
    }

    @Test
    fun `a pairing payload survives encode and decode byte for byte`() {
        val original = payload()
        val encoded = original.encode()

        val decoded = decode(requireNotNull(pairingQrPixels(encoded)))

        assertEquals(encoded, decoded)
    }

    @Test
    fun `the decoded text still parses back into the same payload`() {
        val original = payload()

        val decoded = decode(requireNotNull(pairingQrPixels(original.encode())))

        val parsed = PairingQrPayload.parse(decoded)
        assertTrue(parsed is PairingQrPayload.ParseResult.Parsed, "expected Parsed, was $parsed")
        assertEquals(original, parsed.payload)
    }

    @Test
    fun `a payload zxing cannot fit degrades to null rather than throwing`() {
        assertNull(pairingQrPixels("x".repeat(10_000)))
    }

    @Test
    fun `every pixel is one of the two opaque scanner colours`() {
        val pixels = requireNotNull(pairingQrPixels(payload().encode()))

        val distinct = pixels.argb.distinct().sorted()
        assertEquals(listOf(QR_DARK, QR_LIGHT).sorted(), distinct)
    }

    @Test
    fun `the quiet zone is wide enough for a scanner`() {
        val pixels = requireNotNull(pairingQrPixels(payload().encode()))

        // Measured, not asserted structurally: zxing centres the matrix inside the requested size,
        // so the leftover always shows up as a light border even with MARGIN=0. Only the border's
        // *thickness* distinguishes a real 4-module quiet zone (4 x the module size, tens of px at
        // 512) from centring slop (single digits). A test that merely checks "the outer ring is
        // light" passes with the quiet zone switched off entirely.
        var border = 0
        while (border < pixels.height &&
            (0 until pixels.width).all { pixels.argb[border * pixels.width + it] == QR_LIGHT }
        ) {
            border++
        }

        assertTrue(border >= MIN_QUIET_ZONE_PX, "light border was only ${border}px; quiet zone lost")
    }

    private companion object {
        // Our payloads land around version 7-10, so a module is ~10px at 512 and four of them is
        // ~40. Centring slop alone is under ten. Anything above 24 can only be a real quiet zone.
        const val MIN_QUIET_ZONE_PX = 24
    }
}
