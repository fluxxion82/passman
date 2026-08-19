package ai.passman.design.core

import androidx.compose.foundation.background
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.requiredSizeIn
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.PopupProperties

@Composable
actual fun DropdownField(
    modifier: Modifier,
    // interactionSource: MutableInteractionSource,
    enabled: Boolean,
    label: String,
    value: String,
    items: List<String>,
    selectedIndex: Int,
    onItemSelected: (index: Int, item: String) -> Unit,
    selectedItemToString: (String) -> String,
) {
    var expanded by remember { mutableStateOf(false) }
    val interactionSource: MutableInteractionSource = remember { MutableInteractionSource() }

    if (interactionSource.collectIsPressedAsState().value) {
        expanded = !expanded
    }

    Box(
        modifier = modifier
    ) {
        OutlinedTextField(
            label = { Text(text = label, color = MaterialTheme.colorScheme.onSurface) },
            value = value,
            enabled = enabled,
            // Out of the tab ring: this anchor only ever opened on pointer press (the menu has
            // no keyboard path), so keyboard users could Tab onto a control Enter can't open —
            // and the declined Enter fell through to the form's submit. Skipping it is honest,
            // not a regression; mouse and touch behavior are unchanged.
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface)
                .focusProperties { canFocus = false },
            trailingIcon = {
                val icon = if (expanded) {
                    Icons.Filled.KeyboardArrowUp
                } else {
                    Icons.Filled.ArrowDropDown
                }
                Icon(icon, "", tint = MaterialTheme.colorScheme.onSurface)
            },
            onValueChange = { },
            readOnly = true,
            interactionSource = interactionSource,
            textStyle = TextStyle(color = MaterialTheme.colorScheme.onSurface, fontSize = 14.sp)
        )

        DropdownMenu(
            modifier = Modifier
                .background(MaterialTheme.colorScheme.surface)
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
                        onItemSelected(items.indexOf(it), it)
                        expanded = false
                    },
                    text = {
                        Text(it, modifier = Modifier.wrapContentWidth(), color = MaterialTheme.colorScheme.onSurface)
                    },
                )
            }
        }
    }
}
