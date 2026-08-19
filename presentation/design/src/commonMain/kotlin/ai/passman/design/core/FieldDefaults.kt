package ai.passman.design.core

import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.TextFieldColors
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.contentColorFor
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.takeOrElse

@Composable
fun passmanTextFieldColors(): TextFieldColors = TextFieldDefaults.colors(
    focusedContainerColor = MaterialTheme.colorScheme.surface,
    unfocusedContainerColor = MaterialTheme.colorScheme.surface,
    disabledContainerColor = MaterialTheme.colorScheme.surface,
    focusedTextColor = MaterialTheme.colorScheme.onSurface,
    unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
    focusedTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
    unfocusedTrailingIconColor = MaterialTheme.colorScheme.onSurfaceVariant,
)

@Composable
fun passmanButtonColors(
    // Primary, not surface: a surface-filled default rendered buttons invisible on the
    // surface-painted screens (white pill on white screen in light mode). The Login-family
    // screens that paint their root primary and want white pills pass surface explicitly.
    // Primary #00BFFF is only 2.12:1 on white, so primary-filled buttons also need the
    // 1dp outline edge — use core/button/PassmanButtons.kt instead of raw Button.
    containerColor: Color = MaterialTheme.colorScheme.primary,
): ButtonColors = ButtonDefaults.buttonColors(
    containerColor = containerColor,
    contentColor = MaterialTheme.colorScheme.contentColorFor(containerColor)
        .takeOrElse { MaterialTheme.colorScheme.onSurface },
)
