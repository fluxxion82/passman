package ai.passman.design.core

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
fun DetailsTopBar(
    onEditClicked: () -> Unit,
    onDeleteClicked: () -> Unit,
) {
    Row(
        horizontalArrangement = Arrangement.End,
        modifier = Modifier
            .fillMaxWidth()
    ) {
        IconButton(onClick = {
            onEditClicked()
        }) {
            Icon(imageVector = Icons.Filled.Edit, "edit password")
        }

        IconButton(onClick = onDeleteClicked) {
            Icon(imageVector = Icons.Filled.Delete, "delete password")
        }
    }
}
