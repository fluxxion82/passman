package ai.passman.design

import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.graphics.Color

/** The single source of color truth; see docs/plans/2026-08-12-material3-theming-plan.md. */
val PassmanLightColorScheme = lightColorScheme(
    primary = deepSkyBlue,
    onPrimary = black,
    secondary = grey,
    // The secondary trio: M3 components that consume the secondary-container roles (filled
    // tonal buttons/chips, menus, date pickers) would otherwise fall back to the stock M3
    // lavender — the exact purple-fallback Task 1 exists to remove. Values reuse palette
    // seeds only.
    onSecondary = black,
    secondaryContainer = smoke,
    onSecondaryContainer = black,
    surface = white,
    onSurface = black,
    background = white,
    onBackground = black,
    surfaceVariant = smoke,
    // The plan role-map caveat sanctions this: ash is only 1.84:1 on white, so steel keeps M3
    // field labels and placeholders readable. Trailing icons deliberately shift ash -> steel.
    onSurfaceVariant = steel,
    outline = steel,
    // Ash is only 1.84:1 on white — fine here: outlineVariant is a non-text decorative role
    // (hairline dividers, OutlinedButton borders). Unset it falls back to stock M3 lavender.
    outlineVariant = ash,
    error = red,
    onError = white,
    inverseSurface = coalBlack,
    // M3 dialogs, drawer, switch tracks, and snackbar actions use these container roles. Set
    // them explicitly so Task 13/15 component swaps cannot leak stock M3 lavender.
    surfaceContainerLowest = white,
    surfaceContainerLow = white,
    surfaceContainer = smoke,
    surfaceContainerHigh = white,
    surfaceContainerHighest = smoke,
    surfaceBright = white,
    surfaceDim = smoke,
    inversePrimary = deepSkyBlue, // 8.20:1 on inverseSurface coalBlack.
    surfaceTint = deepSkyBlue,
)

// Deliberately blue on the warm surface: 1.92:1 separation; white content remains 6.08:1.
private val darkPrimaryContainer = Color(0xff0A6A8C)
private val darkSecondaryContainer = Color(0xff4D4A44)
private val darkError = Color(0xffFF7C90)
private val darkErrorContainer = Color(0xff7F0D20)
private val darkBackground = Color(0xff35322E)
private val darkSurfaceLowest = Color(0xff2F2C29)
private val darkSurface = Color(0xff3B3833)
private val darkSurfaceContainer = Color(0xff413E39)
private val darkSurfaceHigh = Color(0xff47443E)
private val darkSurfaceHighest = Color(0xff4D4A44)
private val darkSurfaceBright = Color(0xff5C584F)
private val darkSurfaceVariant = Color(0xff545049)

/**
 * The app's dark scheme. Warm charcoal won a five-candidate comparison: its undertone sits on the
 * complement side of the wheel from the #00BFFF primary, maximizing accent contrast. All body-text
 * foreground/background pairs meet WCAG AA.
 */
val PassmanDarkColorScheme = darkColorScheme(
    primary = deepSkyBlue, // onPrimary black: 9.90:1; foreground on surface: 5.50:1
    onPrimary = black,
    primaryContainer = darkPrimaryContainer, // onPrimaryContainer white: 6.08:1
    onPrimaryContainer = white,
    inversePrimary = darkPrimaryContainer, // on inverseSurface smoke: 5.19:1

    secondary = grey, // onSecondary black: 14.25:1
    onSecondary = black,
    secondaryContainer = darkSecondaryContainer, // onSecondaryContainer white: 8.83:1
    onSecondaryContainer = white,

    // Warning and success stay in PassmanExtendedColors, so tertiary keeps the app accent.
    tertiary = deepSkyBlue, // onTertiary black: 9.90:1
    onTertiary = black,
    tertiaryContainer = darkPrimaryContainer, // onTertiaryContainer white: 6.08:1
    onTertiaryContainer = white,

    background = darkBackground, // onBackground white: 12.75:1
    onBackground = white,
    surface = darkSurface, // onSurface white: 11.67:1
    onSurface = white,
    surfaceVariant = darkSurfaceVariant, // onSurfaceVariant white: 8.01:1
    onSurfaceVariant = white,
    surfaceTint = deepSkyBlue,
    inverseSurface = smoke, // inverseOnSurface black: 17.94:1
    inverseOnSurface = black,

    // Error is readable as foreground on the warm surface at 4.74:1; black content is 8.54:1.
    error = darkError,
    onError = black,
    errorContainer = darkErrorContainer, // onErrorContainer white: 10.60:1
    onErrorContainer = white,

    outline = ash, // 6.35:1 against the warm surface
    outlineVariant = steel, // 2.46:1 against the warm surface; suitable for non-text dividers
    scrim = black,

    surfaceBright = darkSurfaceBright, // onSurface white: 7.09:1
    surfaceContainer = darkSurfaceContainer, // onSurface white: 10.64:1
    surfaceContainerHigh = darkSurfaceHigh, // onSurface white: 9.70:1
    surfaceContainerHighest = darkSurfaceHighest, // onSurface white: 8.83:1
    surfaceContainerLow = darkSurface, // onSurface white: 11.67:1
    surfaceContainerLowest = darkSurfaceLowest, // onSurface white: 13.88:1
    surfaceDim = darkBackground, // onSurface white: 12.75:1

    primaryFixed = deepSkyBlue, // onPrimaryFixed black: 9.90:1
    primaryFixedDim = deepSkyBlue, // onPrimaryFixed black: 9.90:1
    onPrimaryFixed = black,
    onPrimaryFixedVariant = black,
    secondaryFixed = grey, // onSecondaryFixed black: 14.25:1
    secondaryFixedDim = ash, // onSecondaryFixed black: 11.42:1
    onSecondaryFixed = black,
    onSecondaryFixedVariant = black,
    tertiaryFixed = deepSkyBlue, // onTertiaryFixed black: 9.90:1
    tertiaryFixedDim = deepSkyBlue, // onTertiaryFixed black: 9.90:1
    onTertiaryFixed = black,
    onTertiaryFixedVariant = black,
)
