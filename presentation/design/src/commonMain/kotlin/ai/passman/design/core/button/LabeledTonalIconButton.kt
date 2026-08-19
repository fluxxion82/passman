package ai.passman.design.core.button

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

@Composable
fun LabeledTonalIconButton(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    contentDescription: String = label,
    // 21:1 on the (transparent-container) light surface, 11.67:1 on the dark surface.
    tint: Color = MaterialTheme.colorScheme.onSurface,
    labelMaxLines: Int = 1,
) {
    Column(
        modifier = modifier
            .width(72.dp)
            .padding(horizontal = 4.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        // Outlined, not filled-tonal: the tonal secondaryContainer (smoke) was only 1.17:1
        // against the white surface, so the button read as a bare icon in light mode. The
        // outline edge is steel on white 4.74:1 (light) / ash on the dark surface 6.35:1.
        OutlinedIconButton(
            onClick = onClick,
            modifier = Modifier.size(48.dp),
            border = passmanButtonBorder(),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = contentDescription,
                tint = tint,
            )
        }
        Text(
            modifier = Modifier.padding(top = 4.dp),
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.inverseSurface,
            textAlign = TextAlign.Center,
            maxLines = labelMaxLines,
            // Degrade visibly instead of silently clipping at large font scales.
            overflow = TextOverflow.Ellipsis,
        )
    }
}
