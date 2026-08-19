package ai.passman.design.util

import androidx.compose.runtime.Composable

@Composable
actual fun PlatformBackHandler(enabled: Boolean, onBack: () -> Unit) {
    // No-op on iOS; back gestures are handled by the SwiftUI layer.
}
