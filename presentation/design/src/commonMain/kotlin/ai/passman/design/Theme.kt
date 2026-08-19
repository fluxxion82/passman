package ai.passman.design

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import ai.passman.domain.settings.model.ThemeMode

@Composable
fun PassmanTheme(
    themeMode: ThemeMode = ThemeMode.System,
    content: @Composable () -> Unit,
) {
    val darkTheme = when (themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
    val scheme = if (darkTheme) PassmanDarkColorScheme else PassmanLightColorScheme
    val extended = if (darkTheme) PassmanDarkExtendedColors else PassmanLightExtendedColors
    CompositionLocalProvider(LocalPassmanExtendedColors provides extended) {
        MaterialTheme(
            colorScheme = scheme,
            typography = PassmanM3Typography,
            content = content,
        )
    }
}
