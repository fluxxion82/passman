package ai.passman.design.core

import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier

/** One entry in an [OverflowMenuAction]'s dropdown. */
data class OverflowMenuItem(
    val label: String,
    val onClick: () -> Unit,
)

/**
 * A standard M3 top-bar overflow affordance: a MoreVert icon button that opens a dropdown of
 * [items]. Meant to sit in a `TopAppBar`'s actions slot next to the screen's primary action
 * icons; the menu closes itself before invoking the selected item's `onClick`.
 */
@Composable
fun OverflowMenuAction(
    items: List<OverflowMenuItem>,
    modifier: Modifier = Modifier,
    contentDescription: String = "More options",
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        IconButton(onClick = { expanded = true }) {
            Icon(
                imageVector = Icons.Filled.MoreVert,
                contentDescription = contentDescription,
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            items.forEach { item ->
                DropdownMenuItem(
                    text = { Text(item.label) },
                    onClick = {
                        expanded = false
                        item.onClick()
                    },
                )
            }
        }
    }
}
