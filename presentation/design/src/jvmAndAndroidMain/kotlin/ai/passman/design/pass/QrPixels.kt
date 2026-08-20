package ai.passman.design.pass

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

// Encoded once at a fixed size and scaled by the caller's modifier; the payload is short enough
// that zxing picks a low version, so 512px leaves several device pixels per module.
internal const val QR_PIXELS = 512

// Deliberately not theme colours: a scanner needs dark-on-light contrast, and an inverted or
// tinted QR fails to decode on many phones. Opaque ARGB on both platforms — Android's ARGB_8888
// bitmap needs the alpha byte, and AWT's TYPE_INT_RGB raster discards it, so one pair of values
// is correct for both.
internal const val QR_DARK = 0xFF000000.toInt()
internal const val QR_LIGHT = 0xFFFFFFFF.toInt()

private val encodeHints = mapOf<EncodeHintType, Any>(
    // Four modules is the quiet zone the QR spec requires. Below it, a scanner has nothing to
    // separate the symbol from whatever the card draws around it, which is most of the failures
    // that look like "the camera just won't pick it up".
    EncodeHintType.MARGIN to 4,
    // Level M over zxing's default L: the pairing payload is short, so the extra redundancy costs
    // a version at most, and it buys back the glare and screen-moiré a phone camera reads through.
    EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
)

/**
 * A rendered QR raster in opaque ARGB, row-major. Square, and at least [QR_PIXELS] on a side.
 *
 * Not a data class on purpose: the generated `equals`/`hashCode` would compare [argb] by identity,
 * which is the wrong answer for a pixel buffer and nothing here needs either.
 */
internal class QrPixels(val width: Int, val height: Int, val argb: IntArray)

/**
 * Encodes [content] as a QR raster, or returns null if zxing cannot fit the payload.
 *
 * Null rather than an exception because the only caller is a composable: a code that fails to
 * encode must degrade to a placeholder, not take the screen it sits on down with it.
 */
internal fun pairingQrPixels(content: String, size: Int = QR_PIXELS): QrPixels? = runCatching {
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, encodeHints)
    // The requested size is a floor, not a promise: zxing rounds up to a whole number of modules,
    // so the matrix can come back larger than `size`. Reading it at the size we asked for would
    // crop the symbol and produce an image no scanner can decode.
    val width = matrix.width
    val height = matrix.height
    val argb = IntArray(width * height)
    for (y in 0 until height) {
        val row = y * width
        for (x in 0 until width) {
            argb[row + x] = if (matrix[x, y]) QR_DARK else QR_LIGHT
        }
    }
    QrPixels(width, height, argb)
}.getOrNull()
