package ai.passman.design.pgp

import ai.passman.design.core.button.LabeledTonalIconButton
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Share
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun KeyDetailsActionRow(
    onToolsClicked: () -> Unit,
    @Suppress("UNUSED_PARAMETER") onChangeExpirationDate: () -> Unit,
    onChangePassword: () -> Unit,
    onShareKeyClick: () -> Unit,
    onDeleteKeyClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    // weight(1f) everywhere: fixed widths overflowed 360dp screens and pushed Delete off-screen.
    Row(
        modifier = modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        LabeledTonalIconButton(
            icon = Icons.Filled.Build,
            label = "Tools",
            onClick = onToolsClicked,
            modifier = Modifier.weight(1f),
        )
        LabeledTonalIconButton(
            icon = Icons.Filled.Lock,
            label = "Password",
            onClick = onChangePassword,
            modifier = Modifier.weight(1f),
        )
        LabeledTonalIconButton(
            icon = Icons.Filled.Share,
            label = "Share public key",
            onClick = onShareKeyClick,
            modifier = Modifier.weight(1f),
            // The label states what Share actually emits; two lines so it survives narrow slots.
            labelMaxLines = 2,
        )
        LabeledTonalIconButton(
            icon = Icons.Filled.DeleteForever,
            label = "Delete",
            onClick = onDeleteKeyClick,
            modifier = Modifier.weight(1f),
        )
    }
}
