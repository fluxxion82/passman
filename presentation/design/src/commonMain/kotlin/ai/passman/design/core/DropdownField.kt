package ai.passman.design.core

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
expect fun DropdownField(
    modifier: Modifier = Modifier,
    // interactionSource: MutableInteractionSource = remember { MutableInteractionSource() },
    enabled: Boolean = true,
    label: String,
    value: String,
    items: List<String>,
    selectedIndex: Int = -1,
    onItemSelected: (index: Int, item: String) -> Unit,
    selectedItemToString: (String) -> String = { it },
)
