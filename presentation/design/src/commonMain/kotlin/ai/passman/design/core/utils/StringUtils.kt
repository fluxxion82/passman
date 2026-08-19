package ai.passman.design.core.utils

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle

fun colorizeString(
    input: String,
    digitColor: Color,
    letterColor: Color,
    symbolColor: Color,
): AnnotatedString {
    return buildAnnotatedString {
        input.forEach { char ->
            if (char.isDigit()) {
                withStyle(style = SpanStyle(color = digitColor, fontWeight = FontWeight.Bold)) {
                    append(char)
                }
            } else if (char.isLetter()) {
                withStyle(style = SpanStyle(color = letterColor, fontWeight = FontWeight.Bold)) {
                    append(char)
                }
            } else {
                withStyle(style = SpanStyle(color = symbolColor, fontWeight = FontWeight.Bold)) {
                    append(char)
                }
            }
        }
    }
}
