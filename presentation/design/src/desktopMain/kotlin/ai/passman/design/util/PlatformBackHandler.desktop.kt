package ai.passman.design.util

import androidx.compose.runtime.Composable

@Composable
actual fun PlatformBackHandler(enabled: Boolean, onBack: () -> Unit) {
    // No-op on desktop; back is handled by top-bar icon button.
}
