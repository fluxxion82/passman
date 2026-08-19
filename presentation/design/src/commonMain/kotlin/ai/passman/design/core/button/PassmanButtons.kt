package ai.passman.design.core.button

import ai.passman.design.core.passmanButtonColors
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp

/**
 * The standard 1dp edge for Passman buttons, drawn with the outline role:
 * steel on white 4.74:1 (light); ash on the warm dark surface #3B3833 6.35:1 and on the
 * dark background #35322E 6.93:1. All clear the 3:1 WCAG non-text minimum.
 */
@Composable
fun passmanButtonBorder(): BorderStroke =
    BorderStroke(1.dp, MaterialTheme.colorScheme.outline)

/**
 * The app's standard filled action button: primary fill plus a 1dp outline edge.
 *
 * The border is load-bearing, not decorative: primary #00BFFF is only 2.12:1 against the
 * light scheme's white surface — below the 3:1 WCAG non-text minimum — so the fill alone
 * cannot delineate the button on a light screen (M3 filled buttons have zero elevation).
 * In dark mode the fill is already 5.50:1 against the warm surface; the border stays for
 * consistency. Content rides contentColorFor(primary) = onPrimary — black in both schemes,
 * 9.90:1 on #00BFFF (see ColorScheme.kt).
 *
 * [containerColor]/[border] overrides exist for one legacy family only: the Login-style
 * screens that paint their root primary and draw white surface pills on it (2.12:1
 * container-on-backdrop, judged visible; kept borderless so the family stays uniform).
 * New call sites should not override them.
 */
@Composable
fun PassmanPrimaryButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = ButtonDefaults.shape,
    containerColor: Color = MaterialTheme.colorScheme.primary,
    // No border when disabled: a full-strength edge over the 12%-alpha disabled fill would
    // make the button read as enabled.
    border: BorderStroke? = if (enabled) passmanButtonBorder() else null,
    content: @Composable RowScope.() -> Unit,
) {
    Button(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        shape = shape,
        colors = passmanButtonColors(containerColor = containerColor),
        border = border,
        content = content,
    )
}

/** Text convenience over the slot variant: bold single-line label in the content color. */
@Composable
fun PassmanPrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = ButtonDefaults.shape,
    fontSize: TextUnit = TextUnit.Unspecified,
    containerColor: Color = MaterialTheme.colorScheme.primary,
    border: BorderStroke? = if (enabled) passmanButtonBorder() else null,
) {
    PassmanPrimaryButton(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        shape = shape,
        containerColor = containerColor,
        border = border,
    ) {
        Text(
            text = text,
            fontSize = fontSize,
            fontWeight = FontWeight.Bold,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/**
 * The app's standard secondary action button: outlined, transparent container.
 *
 * The border is set explicitly because stock [OutlinedButton] resolves its own token and
 * must not drift from the primary button's edge: outline is steel on white 4.74:1 (light) /
 * ash on the warm surface 6.35:1 (dark). Content is onSurface — 21:1 on white, 11.67:1 on
 * the dark surface — instead of the M3 default primary label, which is illegible at 2.12:1
 * on white.
 */
@Composable
fun PassmanSecondaryButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = ButtonDefaults.outlinedShape,
    content: @Composable RowScope.() -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        shape = shape,
        colors = ButtonDefaults.outlinedButtonColors(
            contentColor = MaterialTheme.colorScheme.onSurface,
        ),
        // Disabled fades the edge to 12% alpha, matching M3's stock outlinedButtonBorder,
        // so a disabled outlined button cannot read as enabled.
        border = if (enabled) {
            passmanButtonBorder()
        } else {
            BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.12f))
        },
        content = content,
    )
}

/** Text convenience over the slot variant: single-line label in the content color. */
@Composable
fun PassmanSecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    shape: Shape = ButtonDefaults.outlinedShape,
    fontSize: TextUnit = TextUnit.Unspecified,
) {
    PassmanSecondaryButton(
        onClick = onClick,
        modifier = modifier,
        enabled = enabled,
        shape = shape,
    ) {
        Text(
            text = text,
            fontSize = fontSize,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
