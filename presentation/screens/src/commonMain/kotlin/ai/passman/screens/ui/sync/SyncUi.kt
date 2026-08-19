package ai.passman.screens.ui.sync

import ai.passman.domain.settings.friendlyMessage
import ai.passman.domain.settings.model.SyncSessionState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

private const val SYNC_TIMEOUT_SECONDS = 60

@Composable
fun RowScope.SyncIconAction(
    syncState: SyncSessionState,
    contentDescription: String,
    onClick: () -> Unit,
) {
    val inProgress = syncState is SyncSessionState.AwaitingPeer || syncState is SyncSessionState.Syncing
    IconButton(onClick = onClick) {
        if (inProgress) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                // Lives in the primary top bar — a primary spinner is invisible there.
                color = MaterialTheme.colorScheme.onPrimary,
            )
        } else {
            Icon(
                imageVector = if (syncState is SyncSessionState.Syncing) Icons.Default.Sync else Icons.Default.Refresh,
                contentDescription = contentDescription,
                tint = MaterialTheme.colorScheme.onPrimary,
            )
        }
    }
}

@Composable
fun SyncBanner(syncState: SyncSessionState, onCancel: () -> Unit) {
    when (syncState) {
        is SyncSessionState.AwaitingPeer -> {
            val remaining = (SYNC_TIMEOUT_SECONDS - syncState.elapsedSeconds).coerceAtLeast(0)
            Banner(
                primary = "Waiting for peer at ${syncState.host}…",
                secondary = "Tap Sync on the other device. ${remaining}s remaining.",
                onCancel = onCancel,
            )
        }
        is SyncSessionState.Syncing -> {
            Banner(
                primary = "Syncing with ${syncState.host}…",
                secondary = null,
                onCancel = onCancel,
            )
        }
        else -> Unit
    }
}

@Composable
private fun Banner(primary: String, secondary: String?, onCancel: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f))
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        CircularProgressIndicator(
            modifier = Modifier.size(18.dp),
            strokeWidth = 2.dp,
            color = MaterialTheme.colorScheme.primary,
        )
        Column(
            modifier = Modifier
                .padding(start = 12.dp)
                .weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(text = primary, color = MaterialTheme.colorScheme.onSurface)
            if (secondary != null) {
                Text(text = secondary, color = MaterialTheme.colorScheme.outline)
            }
        }
        TextButton(onClick = onCancel) { Text("Cancel") }
    }
}

@Composable
fun SyncSessionSnackbarEffect(
    syncState: SyncSessionState,
    snackbarHostState: SnackbarHostState,
    successMessage: String,
    onChooseDevice: () -> Unit,
    onAcknowledge: () -> Unit,
) {
    LaunchedEffect(syncState) {
        when (syncState) {
            is SyncSessionState.Success -> {
                snackbarHostState.showSnackbar(message = successMessage)
                onAcknowledge()
            }
            is SyncSessionState.Error -> {
                val message = friendlyMessage(syncState.failure, syncState.message)
                val result = snackbarHostState.showSnackbar(
                    message = message,
                    actionLabel = "Devices",
                )
                if (result == SnackbarResult.ActionPerformed) onChooseDevice()
                onAcknowledge()
            }
            else -> Unit
        }
    }
}
