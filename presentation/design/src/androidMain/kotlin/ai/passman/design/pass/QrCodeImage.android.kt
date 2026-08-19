package ai.passman.design.pass

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

// Encoded once at a fixed size and scaled by the caller's modifier; the payload is short enough
// that zxing picks a low version, so 512px leaves several device pixels per module.
private const val QR_PIXELS = 512

// Deliberately not theme colours: a scanner needs dark-on-light contrast, and an inverted or
// tinted QR fails to decode on many phones.
private const val QR_DARK = 0xFF000000.toInt()
private const val QR_LIGHT = 0xFFFFFFFF.toInt()

private val encodeHints = mapOf<EncodeHintType, Any>(
    // Four modules is the quiet zone the QR spec requires. Below it, a scanner has nothing to
    // separate the symbol from whatever the card draws around it, which is most of the failures
    // that look like "the camera just won't pick it up".
    EncodeHintType.MARGIN to 4,
    // Level M over zxing's default L: the pairing payload is short, so the extra redundancy costs
    // a version at most, and it buys back the glare and screen-moiré a phone camera reads through.
    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
)

@Composable
actual fun QrCodeImage(content: String, modifier: Modifier) {
    val bitmap = remember(content) {
        // zxing throws on a payload it cannot fit, and composition is not a place to throw from:
        // a code that fails to encode must degrade to the placeholder the way iOS already does,
        // not take the Trusted Devices screen down with it.
        runCatching {
            val matrix = QRCodeWriter().encode(
                content,
                BarcodeFormat.QR_CODE,
                QR_PIXELS,
                QR_PIXELS,
                encodeHints,
            )
            // The requested size is a floor, not a promise: zxing rounds up to a whole number of
            // modules, so the matrix can come back larger than QR_PIXELS. Reading it at the size
            // we asked for would crop the symbol and produce an image no scanner can decode.
            val width = matrix.width
            val height = matrix.height
            val pixels = IntArray(width * height)
            for (y in 0 until height) {
                val row = y * width
                for (x in 0 until width) {
                    pixels[row + x] = if (matrix[x, y]) QR_DARK else QR_LIGHT
                }
            }
            Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888).asImageBitmap()
        }.getOrNull()
    }
    if (bitmap == null) {
        Box(modifier = modifier.background(MaterialTheme.colorScheme.surfaceVariant))
        return
    }
    Image(
        bitmap = bitmap,
        contentDescription = "Pairing QR code",
        modifier = modifier,
        // Nearest-neighbour keeps module edges square when the image is scaled up.
        filterQuality = FilterQuality.None,
    )
}
