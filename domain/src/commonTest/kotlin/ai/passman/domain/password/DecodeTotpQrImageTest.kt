package ai.passman.domain.password

import ai.passman.domain.password.service.QrCodeService
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class DecodeTotpQrImageTest {
    private class FakeQrCodeService(private val result: QrCodeService.DecodeResult) : QrCodeService {
        override suspend fun decodeImageFile(path: String): QrCodeService.DecodeResult = result
    }

    private fun decoder(result: QrCodeService.DecodeResult) = DecodeTotpQrImage(FakeQrCodeService(result))

    private fun decoder(payload: String) = decoder(QrCodeService.DecodeResult.Payload(payload))

    @Test
    fun `a default-parameter otpauth qr yields the bare secret`() = runTest {
        val uri = "otpauth://totp/Example:mia@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        assertEquals(DecodeTotpQrImage.Result.Seed("JBSWY3DPEHPK3PXP"), decoder(uri)("/tmp/qr.png"))
    }

    @Test
    fun `non-default parameters keep the full uri`() = runTest {
        val uri = "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=8"
        assertEquals(DecodeTotpQrImage.Result.Seed(uri), decoder(uri)("/tmp/qr.png"))
    }

    @Test
    fun `a raw base32 qr also counts as a seed`() = runTest {
        assertEquals(
            DecodeTotpQrImage.Result.Seed("JBSWY3DPEHPK3PXP"),
            decoder("JBSWY3DPEHPK3PXP")("/tmp/qr.png"),
        )
    }

    @Test
    fun `an image without a readable qr reports NoQrFound`() = runTest {
        assertEquals(
            DecodeTotpQrImage.Result.NoQrFound,
            decoder(QrCodeService.DecodeResult.NoQrFound)("/tmp/photo.png"),
        )
    }

    @Test
    fun `an unreadable image file reports UnreadableImage`() = runTest {
        assertEquals(
            DecodeTotpQrImage.Result.UnreadableImage,
            decoder(QrCodeService.DecodeResult.UnreadableImage)("/tmp/photo.heic"),
        )
    }

    @Test
    fun `a qr that is not a totp setup code reports NotTotp`() = runTest {
        assertEquals(
            DecodeTotpQrImage.Result.NotTotp,
            decoder("https://example.com/menu")("/tmp/menu.png"),
        )
    }

    @Test
    fun `the decoded payload is trimmed`() = runTest {
        assertEquals(
            DecodeTotpQrImage.Result.Seed("JBSWY3DPEHPK3PXP"),
            decoder("  JBSWY3DPEHPK3PXP\n")("/tmp/qr.png"),
        )
    }
}
