package ai.passman.design.pgp

import ai.passman.design.core.EmptyState
import ai.passman.domain.pgp.model.PgpKeyPair
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
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun PgpKeysList(
    keys: List<PgpKeyPair>,
    selectedIds: Set<Long>,
    onKeyClick: (PgpKeyPair) -> Unit,
    onKeyLongPress: (PgpKeyPair) -> Unit,
    onCreateKey: () -> Unit,
    isLoading: Boolean,
) {
    if (keys.isEmpty() && !isLoading) {
        EmptyState(
            icon = Icons.Filled.Lock,
            title = "No PGP keys",
            body = "Create a key pair, or sync keys from a paired device.",
            actionLabel = "Create key",
            onAction = onCreateKey,
        )
        return
    }

    LazyColumn(
        verticalArrangement = Arrangement.spacedBy(6.dp),
        contentPadding = PaddingValues(vertical = 8.dp),
    ) {
        items(items = keys, key = { it.publicKey.keyId }) { key ->
            PgpKeysListItem(
                item = key,
                isSelected = key.publicKey.keyId in selectedIds,
                onKeyClick = onKeyClick,
                onKeyLongPress = onKeyLongPress,
            )
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PgpKeysListItem(
    item: PgpKeyPair,
    isSelected: Boolean,
    onKeyClick: (PgpKeyPair) -> Unit,
    onKeyLongPress: (PgpKeyPair) -> Unit,
) {
    val selectedTint = MaterialTheme.colorScheme.primary
        .copy(alpha = 0.2f)
        .compositeOver(MaterialTheme.colorScheme.surface)
    val itemColor = if (isSelected) selectedTint else MaterialTheme.colorScheme.surface
    val keyId = item.publicKey.fingerprint.ifBlank { longToHex(item.publicKey.keyId) }

    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .combinedClickable(
                onClick = { onKeyClick(item) },
                onLongClick = { onKeyLongPress(item) },
            ),
        colors = ListItemDefaults.colors(containerColor = itemColor),
        headlineContent = {
            Text(
                text = item.publicKey.userIds.firstOrNull()?.name.orEmpty().ifBlank { "Unnamed key" },
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
            )
        },
        supportingContent = {
            Text(
                text = keyId,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        },
        trailingContent = {
            TypeChip(label = if (item.secretKey != null) "Sec/Pub" else "Pub")
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
