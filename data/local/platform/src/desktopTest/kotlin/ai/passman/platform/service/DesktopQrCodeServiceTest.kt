package ai.passman.platform.service

import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.password.service.QrCodeService
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import java.awt.image.BufferedImage
import java.io.File
import java.nio.file.Files
import javax.imageio.ImageIO
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.runBlocking

class DesktopQrCodeServiceTest {
    private val service = DesktopQrCodeService()
    private val root = Files.createTempDirectory("qr-test").toFile()

    @AfterTest
    fun tearDown() {
        root.deleteRecursively()
    }

    private fun qrPng(payload: String): String {
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 300, 300)
        val image = BufferedImage(matrix.width, matrix.height, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until matrix.width) {
            for (y in 0 until matrix.height) {
                image.setRGB(x, y, if (matrix.get(x, y)) 0x000000 else 0xFFFFFF)
            }
        }
        val file = File(root, "qr.png")
        ImageIO.write(image, "png", file)
        return file.absolutePath
    }

    @Test
    fun `an encoded otpauth uri survives the round trip`() = runBlocking<Unit> {
        val uri = "otpauth://totp/Example:mia@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        assertEquals(QrCodeService.DecodeResult.Payload(uri), service.decodeImageFile(qrPng(uri)))
    }

    @Test
    fun `a transparent-background qr png decodes`() = runBlocking<Unit> {
        // Web QR images routinely ship as PNGs with a transparent background; unflattened, the
        // luminance source reads transparent pixels as black and the code drowns.
        val uri = "otpauth://totp/Example:mia@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        val matrix = QRCodeWriter().encode(uri, BarcodeFormat.QR_CODE, 300, 300)
        val image = BufferedImage(matrix.width, matrix.height, BufferedImage.TYPE_INT_ARGB)
        for (x in 0 until matrix.width) {
            for (y in 0 until matrix.height) {
                image.setRGB(x, y, if (matrix.get(x, y)) 0xFF000000.toInt() else 0x00000000)
            }
        }
        val file = File(root, "transparent.png")
        ImageIO.write(image, "png", file)
        assertEquals(QrCodeService.DecodeResult.Payload(uri), service.decodeImageFile(file.absolutePath))
    }

    @Test
    fun `a pairing payload survives the whole encode-render-scan-parse chain`() = runBlocking<Unit> {
        // The one link the unit tests on either end cannot cover: `PairingQrPayload` round-trips
        // through its own parser, and the decoder round-trips through zxing, but nothing else checks
        // that the exact string the shower renders comes back off a scanned image byte-for-byte.
        // Base64url's `-`/`_` and mixed case push the code out of QR alphanumeric mode into byte
        // mode, so a payload that grew past the chosen image size — or one that started emitting a
        // character the encoder mangles — would only ever surface with a camera in hand.
        val payload = PairingQrPayload(
            host = "192.0.2.10",
            port = PairingQrPayload.DEFAULT_PAIRING_PORT,
            digest = ByteArray(32) { (it + 1).toByte() },
            nonce = ByteArray(32) { (0xF0 - it).toByte() },
        )

        val scanned = service.decodeImageFile(qrPng(payload.encode()))

        val text = assertIs<QrCodeService.DecodeResult.Payload>(scanned).text
        assertEquals(payload.encode(), text)
        assertEquals(payload, assertIs<PairingQrPayload.ParseResult.Parsed>(PairingQrPayload.parse(text)).payload)
    }

    @Test
    fun `an image without a qr reports NoQrFound`() = runBlocking<Unit> {
        val blank = File(root, "blank.png")
        ImageIO.write(BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB), "png", blank)
        assertEquals(QrCodeService.DecodeResult.NoQrFound, service.decodeImageFile(blank.absolutePath))
    }

    @Test
    fun `a file that is not an image reports UnreadableImage`() = runBlocking<Unit> {
        val text = File(root, "not-an-image.png")
        text.writeText("definitely not png bytes")
        assertEquals(QrCodeService.DecodeResult.UnreadableImage, service.decodeImageFile(text.absolutePath))
    }

    @Test
    fun `a missing file reports UnreadableImage`() = runBlocking<Unit> {
        assertEquals(
            QrCodeService.DecodeResult.UnreadableImage,
            service.decodeImageFile(File(root, "absent.png").absolutePath),
        )
    }
}
