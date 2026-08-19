package ai.passman.design.core

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.requiredSizeIn
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.PopupProperties

@Composable
fun DropdownContainer(
    backgroundColor: Color,
    expanded: Boolean,
    onDropdownItemSelected: (index: Int, item: String) -> Unit,
    items: List<String>,
) {
    var expanded by remember { mutableStateOf(expanded) }

    // if (interactionSource.collectIsPressedAsState().value) expanded = !expanded

    DropdownMenu(
        modifier = Modifier
            .background(backgroundColor)
            .requiredSizeIn(
                // Max height can only be half the screen size
                maxHeight = (LocalConfiguration.current.screenHeightDp / 2).dp
            ),
        expanded = expanded,
        onDismissRequest = { expanded = false },
        properties = PopupProperties(focusable = false),
    ) {
        items.forEach {
            DropdownMenuItem(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    onDropdownItemSelected(items.indexOf(it), it)
                },
                text = { Text(it, modifier = Modifier.wrapContentWidth()) },
            )
        }
    }
}
