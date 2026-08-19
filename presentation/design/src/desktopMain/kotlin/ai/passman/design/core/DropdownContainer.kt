package ai.passman.design.core

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

@Composable
fun DropdownContainer(
    backgroundColor: Color,
    expanded: Boolean,
    onDropdownItemSelected: (index: Int, item: String) -> Unit,
    items: List<String>,
) {
    DropdownMenu(
        modifier = Modifier.fillMaxWidth().background(backgroundColor),
        expanded = expanded,
        onDismissRequest = {
            // request(false)
        },
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
