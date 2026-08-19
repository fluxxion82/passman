package ai.passman.design

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

@Immutable
data class PassmanExtendedColors(val success: Color, val warning: Color)

val LocalPassmanExtendedColors = staticCompositionLocalOf {
    PassmanExtendedColors(success = Color.Unspecified, warning = Color.Unspecified)
}

val PassmanLightExtendedColors = PassmanExtendedColors(
    success = Color(0xff2E7D32), // 4.6:1 contrast against white; legacy #00FF00 was 1.4:1.
    warning = orange,
)

// Desaturated green avoids pure-green glare against warm charcoal while retaining 5.21:1 contrast.
val PassmanDarkExtendedColors = PassmanExtendedColors(
    success = Color(0xff6DBE8A),
    warning = Color(0xffE3A34B), // 5.34:1 contrast against warm charcoal.
)

val MaterialTheme.passmanColors: PassmanExtendedColors
    @Composable @ReadOnlyComposable get() = LocalPassmanExtendedColors.current
