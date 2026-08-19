package ai.passman.design.core.button

import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.sp

/**
 * Two families share this API: primary-filled actions on surface screens (outline edge
 * mandatory — primary is 2.12:1 on white) and the legacy white surface pills on
 * primary-painted roots (HomeContent/SimpleTwoButtonHome), which stay borderless so they
 * keep matching the Login-family pills. [borderless] declares the family explicitly —
 * inferring it from [containerColor] would be fragile because several light-scheme roles
 * share the same white value. The label color follows the container via
 * passmanButtonColors: onPrimary on primary, onSurface on surface.
 */
@Composable
fun ActionButton(
    modifier: Modifier,
    shape: Shape,
    containerColor: Color,
    buttonText: String,
    buttonTextSize: Int,
    enabled: Boolean = true,
    borderless: Boolean = false,
    copyAction: () -> Unit
) {
    PassmanPrimaryButton(
        text = buttonText,
        onClick = copyAction,
        modifier = modifier.width(IntrinsicSize.Min),
        enabled = enabled,
        shape = shape,
        fontSize = buttonTextSize.sp,
        containerColor = containerColor,
        border = if (borderless || !enabled) null else passmanButtonBorder(),
    )
}
