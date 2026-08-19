package ai.passman.design.pass

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

// zxing is JVM-only; CoreImage's CIQRCodeGenerator can fill this in when the iOS port lands.
// Until then the placeholder just holds the layout slot, like the no-op scanner dialog.
@Composable
actual fun QrCodeImage(content: String, modifier: Modifier) {
    Box(modifier = modifier.background(MaterialTheme.colorScheme.surfaceVariant))
}
