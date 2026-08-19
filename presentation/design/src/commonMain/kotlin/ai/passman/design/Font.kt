package ai.passman.design

import ai.passman.design.generated.resources.Res
import ai.passman.design.generated.resources.inter_regular
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import org.jetbrains.compose.resources.Font

/**
 * Inter (SIL OFL 1.1, see licenses/Inter-OFL.txt) — a single Regular face. The heavier and lighter
 * weights every TextStyle below asks for are synthesized from it, which is what this family has
 * always done. Registering real Inter weights would render better but changes every screen, so it
 * belongs in a deliberate visual pass rather than here.
 */
@Composable
fun getFontFamily(): FontFamily = FontFamily(
    Font(Res.font.inter_regular),
)

val helveticaH1
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.W800,
        fontSize = 96.sp
    )

val textStyle1
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Light,
        fontSize = 60.sp,
        letterSpacing = (-0.5).sp
    )

val textStyle
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Light,
        fontSize = 60.sp,
        letterSpacing = (-0.5).sp
    )

val helveticaH2
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Light,
        fontSize = 60.sp,
        letterSpacing = (-0.5).sp
    )

val helveticaH3
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 48.sp,
        letterSpacing = 0.sp
    )

val helveticaH4
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 34.sp,
        letterSpacing = 0.25.sp
    )

val helveticaH5
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 24.sp,
        letterSpacing = 0.sp
    )

val helveticaH6
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 20.sp,
        letterSpacing = 0.15.sp
    )

val helveticaH7
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 18.sp,
        letterSpacing = 0.22.sp
    )

val helveticaH8
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        letterSpacing = 0.22.sp
    )

val helveticaSubtitle1
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        letterSpacing = 0.15.sp
    )

val helveticaSubtitle2
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        letterSpacing = 0.1.sp
    )

val helveticaSubtitle3
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        letterSpacing = 0.18.sp
    )

val helveticaSubtitle4
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 15.sp,
        letterSpacing = 0.18.sp
    )

val helveticaSubtitle5
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 17.sp,
        letterSpacing = 0.18.sp
    )

val helveticaBody1
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        letterSpacing = 0.5.sp
    )

val helveticaBody2
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        letterSpacing = 0.25.sp
    )

val helveticaBody3
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        letterSpacing = 0.25.sp
    )

val helveticaButton
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        letterSpacing = 1.25.sp
    )

val helveticaCaption
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        letterSpacing = 0.4.sp
    )

val helveticaCaptionItalic
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        letterSpacing = 0.4.sp,
        fontStyle = FontStyle.Italic
    )

val helveticaOverline
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Normal,
        fontSize = 10.sp,
        letterSpacing = 1.5.sp
    )

val helveticaMediumCaption
    @Composable get() = TextStyle(
        fontFamily = getFontFamily(),
        fontWeight = FontWeight.Medium,
        fontSize = 11.sp,
        letterSpacing = 0.4.sp
    )


val PassmanM3Typography
    @Composable get() = androidx.compose.material3.Typography(
        displayLarge = helveticaH1,
        displayMedium = helveticaH2,
        displaySmall = helveticaH3,
        headlineMedium = helveticaH4,
        headlineSmall = helveticaH5,
        titleLarge = helveticaH6,
        titleMedium = helveticaSubtitle1,
        titleSmall = helveticaSubtitle2,
        bodyLarge = helveticaBody1,
        bodyMedium = helveticaBody2,
        labelLarge = helveticaButton,
        bodySmall = helveticaCaption,
        labelSmall = helveticaOverline,
    )
