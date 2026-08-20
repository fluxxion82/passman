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

@Composable
actual fun QrCodeImage(content: String, modifier: Modifier) {
    val bitmap = remember(content) {
        pairingQrPixels(content)?.let {
            Bitmap.createBitmap(it.argb, it.width, it.height, Bitmap.Config.ARGB_8888).asImageBitmap()
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
