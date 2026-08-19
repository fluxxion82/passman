package ai.passman.design.core

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContextualActionBar(
    selectedCount: Int,
    onExit: () -> Unit,
    onDelete: () -> Unit,
    modifier: Modifier = Modifier,
) {
    CenterAlignedTopAppBar(
        title = {
            Text(
                text = "$selectedCount selected",
                fontWeight = FontWeight.Bold,
            )
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.primary,
            titleContentColor = MaterialTheme.colorScheme.onPrimary,
            navigationIconContentColor = MaterialTheme.colorScheme.onPrimary,
            actionIconContentColor = MaterialTheme.colorScheme.onPrimary,
        ),
        navigationIcon = {
            Icon(
                imageVector = Icons.Default.Close,
                contentDescription = "Exit selection",
                modifier = Modifier
                    .padding(start = 8.dp)
                    .clickable { onExit() },
                tint = MaterialTheme.colorScheme.onPrimary,
            )
        },
        actions = {
            Icon(
                imageVector = Icons.Default.Delete,
                contentDescription = "Delete selected",
                modifier = Modifier
                    .padding(end = 8.dp)
                    .clickable { onDelete() },
                tint = MaterialTheme.colorScheme.onPrimary,
            )
        },
        modifier = modifier,
    )
}
