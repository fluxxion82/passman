package ai.passman.design.pass

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

/** Renders [content] as a QR code, or a neutral placeholder on platforms without an encoder. */
@Composable
expect fun QrCodeImage(content: String, modifier: Modifier = Modifier)
