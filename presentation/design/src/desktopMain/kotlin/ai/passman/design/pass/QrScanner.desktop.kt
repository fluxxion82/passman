package ai.passman.design.pass

import androidx.compose.runtime.Composable

// Desktop imports the QR from a screenshot instead — the code usually renders on this same
// machine's screen, where a webcam cannot see it.
actual val cameraQrScanningSupported: Boolean = false

@Composable
actual fun QrCameraScannerDialog(onResult: (String) -> Unit, onDismiss: () -> Unit) = Unit
