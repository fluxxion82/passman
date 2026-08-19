package ai.passman.design.pass

import androidx.compose.runtime.Composable

/** Whether this platform can scan a QR code live with a camera. */
expect val cameraQrScanningSupported: Boolean

/**
 * Full-screen camera scanner. Calls [onResult] once with the first QR payload it reads, then the
 * caller dismisses. Platforms without camera scanning provide a no-op actual and are expected to
 * hide the entry point behind [cameraQrScanningSupported].
 */
@Composable
expect fun QrCameraScannerDialog(onResult: (String) -> Unit, onDismiss: () -> Unit)
