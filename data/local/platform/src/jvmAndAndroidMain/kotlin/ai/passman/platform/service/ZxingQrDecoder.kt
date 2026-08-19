package ai.passman.platform.service

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

/**
 * The shared half of QR decoding: both platforms hand over a plain ARGB pixel grid, so only the
 * image loading (BitmapFactory vs ImageIO) differs per platform.
 */
internal object ZxingQrDecoder {
    private val hints = mapOf(
        DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
        // Screenshots and photos of setup pages are low-contrast often enough to warrant it.
        DecodeHintType.TRY_HARDER to true,
    )

    fun decode(pixels: IntArray, width: Int, height: Int): String? = runCatching {
        val source = RGBLuminanceSource(width, height, flattenOntoWhite(pixels))
        MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    }.getOrNull()

    /**
     * Web QR images routinely ship as PNGs with a transparent background, and the luminance
     * source ignores alpha — an unflattened transparent pixel reads as black and drowns the code.
     */
    private fun flattenOntoWhite(pixels: IntArray): IntArray {
        if (pixels.none { it ushr 24 != 0xFF }) return pixels
        return IntArray(pixels.size) { i ->
            val pixel = pixels[i]
            val alpha = pixel ushr 24
            val red = (pixel shr 16 and 0xFF) * alpha / 0xFF + (0xFF - alpha)
            val green = (pixel shr 8 and 0xFF) * alpha / 0xFF + (0xFF - alpha)
            val blue = (pixel and 0xFF) * alpha / 0xFF + (0xFF - alpha)
            0xFF shl 24 or (red shl 16) or (green shl 8) or blue
        }
    }
}
