package ai.passman.screens.ui.settings

import ai.passman.design.core.button.PassmanSecondaryButton
import ai.passman.design.passmanColors
import ai.passman.design.util.formatDateTime
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.viewmodel.sync.SyncActivityViewModel
import ai.passman.viewmodel.sync.syncArtifactLabel
import ai.passman.viewmodel.sync.syncOutcomeLabel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController

/**
 * This device's sync activity log. A [LazyColumn] of [SyncLogRow] cards, the same status-row
 * vocabulary as [TrustedDeviceRow] — every prior sync stayed opaque to the user, and this screen
 * is the answer: when it ran, with which device, which artifact, and how it ended.
 *
 * An empty list is a fresh install's expected state, not an error, so it gets a plain sentence
 * rather than anything that reads as a failure.
 *
 * [navController] is unused: this screen has nowhere of its own to navigate to (unlike
 * [TrustedDevicesScreen], which takes the same unused parameter) — it is here only so every
 * `composable<Route> { }` block in `settingsGraph` calls its screen the same shape.
 */
@Composable
fun SyncActivityScreen(navController: NavController, presenter: SyncActivityViewModel) {
    val entries by presenter.entries.collectAsState()
    val clearConfirmationVisible by presenter.clearConfirmationVisible.collectAsState()

    if (clearConfirmationVisible) {
        AlertDialog(
            onDismissRequest = presenter::onClearConfirmationDismissed,
            title = { Text("Clear sync activity?") },
            text = {
                Text(
                    "This removes this device's sync history. It never leaves this device and " +
                        "clearing it does not affect your paired devices or anything already synced.",
                )
            },
            confirmButton = {
                TextButton(onClick = presenter::onClearConfirmed) { Text("Clear") }
            },
            dismissButton = {
                TextButton(onClick = presenter::onClearConfirmationDismissed) { Text("Cancel") }
            },
        )
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(text = "Sync activity", fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
            if (entries.isNotEmpty()) {
                PassmanSecondaryButton(text = "Clear log", onClick = presenter::onClearLogClicked)
            }
        }

        if (entries.isEmpty()) {
            Text(
                text = "No syncs have run on this device yet.",
                color = MaterialTheme.colorScheme.onSurface,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // Indexed into the key, not just `at`-`artifact`-`host`: two records for the same
                // artifact and host can land in the same millisecond (concurrent syncs, or a clock
                // with coarse resolution), and a duplicate key throws Compose's duplicate-key
                // exception rather than merely mis-animating a row.
                itemsIndexed(entries, key = { index, entry -> "$index-${entry.at}-${entry.artifact}-${entry.host}" }) { _, entry ->
                    SyncLogRow(entry)
                }
            }
        }
    }
}

@Composable
private fun SyncLogRow(entry: SyncLogEntry) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(text = syncArtifactLabel(entry.artifact), fontWeight = FontWeight.SemiBold)
                Text(
                    text = syncOutcomeLabel(entry.outcome),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = syncOutcomeColor(entry.outcome),
                )
            }
            Text(
                text = entry.deviceName.ifBlank { entry.host },
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = formatDateTime(entry.at),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface,
            )
            if (entry.outcome != SyncLogEntry.OUTCOME_SUCCESS && entry.detail.isNotBlank()) {
                Text(text = entry.detail, fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
            }
        }
    }
}

/**
 * [ai.passman.design.PassmanExtendedColors]' semantic success/warning, not `tertiary` — those two
 * are the app's existing vocabulary for "this went well" / "this needs attention" (see
 * `TrustedDevicesScreen.PairingSecurityLabel`). A failure gets the standard Material error color,
 * distinct from a cancellation: the user stopping a sync on purpose is not the same outcome as it
 * failing on its own. An unrecognised outcome (an older row this build does not know, or a newer
 * one written by a build ahead of this one) is neutral rather than alarming.
 */
@Composable
private fun syncOutcomeColor(outcome: String): Color = when (outcome) {
    SyncLogEntry.OUTCOME_SUCCESS -> MaterialTheme.passmanColors.success
    SyncLogEntry.OUTCOME_CANCELLED -> MaterialTheme.passmanColors.warning
    SyncLogEntry.OUTCOME_FAILED -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurface
}
