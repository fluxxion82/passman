package ai.passman.android.platform.service

import ai.passman.domain.password.service.QrCodeService
import ai.passman.platform.service.ZxingQrDecoder
import android.graphics.BitmapFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal class AndroidQrCodeService : QrCodeService {
    // Off the main thread: a camera-roll photo is a multi-megapixel decode plus a TRY_HARDER scan.
    override suspend fun decodeImageFile(path: String): QrCodeService.DecodeResult =
        withContext(Dispatchers.Default) {
            val bitmap = runCatching { BitmapFactory.decodeFile(path) }.getOrNull()
                ?: return@withContext QrCodeService.DecodeResult.UnreadableImage
            try {
                val pixels = IntArray(bitmap.width * bitmap.height)
                bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
                ZxingQrDecoder.decode(pixels, bitmap.width, bitmap.height)
                    ?.let { QrCodeService.DecodeResult.Payload(it) }
                    ?: QrCodeService.DecodeResult.NoQrFound
            } finally {
                bitmap.recycle()
            }
        }
}
