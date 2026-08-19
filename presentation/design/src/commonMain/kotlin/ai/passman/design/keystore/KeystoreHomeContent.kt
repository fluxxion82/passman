package ai.passman.design.keystore

import ai.passman.design.core.EmptyState
import ai.passman.design.mapper.toDisplayName
import ai.passman.domain.keystore.model.KeyStoreInfo
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun KeystoreHomeContent(
    keystores: List<KeyStoreInfo>,
    selectedIds: Set<String>,
    currentUserName: String?,
    keystoreId: (KeyStoreInfo) -> String,
    onKeystoreClick: (KeyStoreInfo) -> Unit,
    onKeystoreLongPress: (KeyStoreInfo) -> Unit,
    onCreateKeystore: () -> Unit,
    isLoading: Boolean,
) {
    if (keystores.isEmpty() && !isLoading) {
        EmptyState(
            icon = Icons.Filled.Lock,
            title = "No keystores",
            body = "Create a keystore, or sync from a paired device.",
            actionLabel = "Create keystore",
            onAction = onCreateKeystore,
        )
        return
    }

    LazyColumn(
        verticalArrangement = Arrangement.spacedBy(6.dp),
        contentPadding = PaddingValues(vertical = 8.dp),
    ) {
        items(
            items = keystores,
            key = keystoreId,
        ) { store ->
            val id = keystoreId(store)
            val isProtected = currentUserName != null &&
                store.name.equals("$currentUserName.pfx", ignoreCase = true)
            KeystoreListItem(
                keystore = store,
                isSelected = id in selectedIds,
                isProtected = isProtected,
                onKeystoreClick = onKeystoreClick,
                onKeystoreLongPress = onKeystoreLongPress,
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun KeystoreListItem(
    keystore: KeyStoreInfo,
    isSelected: Boolean,
    isProtected: Boolean,
    onKeystoreClick: (KeyStoreInfo) -> Unit,
    onKeystoreLongPress: (KeyStoreInfo) -> Unit,
    modifier: Modifier = Modifier,
) {
    val selectedTint = MaterialTheme.colorScheme.primary
        .copy(alpha = 0.2f)
        .compositeOver(MaterialTheme.colorScheme.surface)
    val itemColor = if (isSelected) selectedTint else MaterialTheme.colorScheme.surface

    ListItem(
        modifier = modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = { onKeystoreClick(keystore) },
                onLongClick = { onKeystoreLongPress(keystore) },
            ),
        colors = ListItemDefaults.colors(containerColor = itemColor),
        headlineContent = {
            Text(
                text = keystore.name,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
            )
        },
        supportingContent = {
            Text(
                text = keystore.path,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        },
        leadingContent = if (isProtected) {
            {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = "Login keystore (protected)",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else null,
        trailingContent = {
            TypeChip(label = keystore.type.toDisplayName())
        },
    )
}

@Composable
private fun TypeChip(label: String) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            text = label,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
        )
    }
}
