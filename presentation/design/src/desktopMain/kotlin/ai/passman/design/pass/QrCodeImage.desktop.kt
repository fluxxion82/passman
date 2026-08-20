package ai.passman.design.pass

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.toComposeImageBitmap
import java.awt.image.BufferedImage

@Composable
actual fun QrCodeImage(content: String, modifier: Modifier) {
    val bitmap = remember(content) {
        pairingQrPixels(content)?.let {
            val image = BufferedImage(it.width, it.height, BufferedImage.TYPE_INT_RGB)
            // One bulk write instead of a quarter-million setRGB calls, each of which re-checks
            // bounds and re-fetches the raster.
            image.setRGB(0, 0, it.width, it.height, it.argb, 0, it.width)
            image.toComposeImageBitmap()
        }
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
