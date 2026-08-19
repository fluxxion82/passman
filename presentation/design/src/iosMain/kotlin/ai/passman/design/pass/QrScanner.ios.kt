package ai.passman.design.pass

import androidx.compose.runtime.Composable

// AVFoundation has native QR detection; wire it up when the iOS port lands.
actual val cameraQrScanningSupported: Boolean = false

@Composable
actual fun QrCameraScannerDialog(onResult: (String) -> Unit, onDismiss: () -> Unit) = Unit
