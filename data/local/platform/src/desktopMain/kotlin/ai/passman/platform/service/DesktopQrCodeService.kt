package ai.passman.platform.service

import ai.passman.domain.password.service.QrCodeService
import ai.passman.logging.KLogger
import java.io.File
import javax.imageio.ImageIO
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DesktopQrCodeService : QrCodeService {
    // Off the Swing EDT: a phone photo is a multi-megapixel read plus a TRY_HARDER scan, long
    // enough to visibly freeze the window when run on the UI dispatcher.
    override suspend fun decodeImageFile(path: String): QrCodeService.DecodeResult =
        withContext(Dispatchers.IO) {
            // ImageIO has no HEIC/WebP readers, so photo-library files land here as null.
            val image = runCatching { ImageIO.read(File(path)) }.getOrNull()
            if (image == null) {
                KLogger.d { "qr decode: unreadable image at $path" }
                return@withContext QrCodeService.DecodeResult.UnreadableImage
            }
            val pixels = image.getRGB(0, 0, image.width, image.height, null, 0, image.width)
            val payload = ZxingQrDecoder.decode(pixels, image.width, image.height)
            KLogger.d { "qr decode: ${image.width}x${image.height}, qr found: ${payload != null}" }
            payload
                ?.let { QrCodeService.DecodeResult.Payload(it) }
                ?: QrCodeService.DecodeResult.NoQrFound
        }
}
