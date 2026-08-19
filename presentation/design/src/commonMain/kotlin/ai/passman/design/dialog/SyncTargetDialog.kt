package ai.passman.design.dialog

import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp

/**
 * Pick a paired device to sync with. [lastSyncedLabel] renders the relative sync time so this
 * module stays clock-free. Tapping a row syncs; the pencil swaps the row into an address editor
 * for a device that moved on the LAN.
 */
@Composable
fun SyncTargetDialog(
    targets: List<TrustedDevice>,
    lastSyncedLabel: (TrustedDevice) -> String,
    onSync: (TrustedDevice) -> Unit,
    onEditHost: (TrustedDevice, String) -> Unit,
    onManageDevices: () -> Unit,
    onDismiss: () -> Unit,
) {
    var editing by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Sync with device") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                targets.forEach { device ->
                    key(device.name) {
                        if (editing == device.name) {
                            HostEditorRow(
                                device = device,
                                onConfirm = { host ->
                                    editing = null
                                    onEditHost(device, host)
                                },
                                onCancel = { editing = null },
                            )
                        } else {
                            DeviceRow(
                                device = device,
                                lastSynced = lastSyncedLabel(device),
                                onClick = { onSync(device) },
                                onEdit = { editing = device.name },
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onManageDevices) { Text("Manage devices") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}

@Composable
private fun DeviceRow(
    device: TrustedDevice,
    lastSynced: String,
    onClick: () -> Unit,
    onEdit: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(
                onClickLabel = "Sync with ${device.name}",
                role = Role.Button,
                onClick = onClick,
            )
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(device.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                "${device.lastHost} · $lastSynced",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )
            if (device.pairingSecurity == PairingSecurity.AwaitingConfirmation) {
                Text(
                    "Needs re-confirmation",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        IconButton(onClick = onEdit) {
            Icon(Icons.Default.Edit, contentDescription = "Edit address for ${device.name}")
        }
    }
}

@Composable
private fun HostEditorRow(
    device: TrustedDevice,
    onConfirm: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var host by remember { mutableStateOf(device.lastHost) }
    // The dialog is its own window with its own focus owner, so the handler must be composed
    // here, inside the dialog content — on the AlertDialog's modifier param it would capture the
    // HOST screen's focus manager (dead Tab, focus never cleared, auto-repeat Enter re-firing
    // the save). Gated the same way as the Save button.
    Column(
        modifier = Modifier.formKeyboardNavigation(
            onSubmit = {
                if (host.isNotBlank()) {
                    onConfirm(host)
                    true
                } else {
                    false
                }
            },
        ),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = host,
                onValueChange = { host = it },
                colors = passmanTextFieldColors(),
                label = { Text(device.name) },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = { onConfirm(host) }, enabled = host.isNotBlank()) { Text("Save") }
            TextButton(onClick = onCancel) { Text("Cancel") }
        }
    }
}

/** Shown when sync is tapped with no pairings: the only fix is the trusted-devices screen. */
@Composable
fun NoSyncTargetsDialog(
    onGoToTrustedDevices: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("No trusted devices") },
        text = { Text("Pair a device first — sync only talks to devices you've explicitly trusted.") },
        confirmButton = {
            TextButton(onClick = onGoToTrustedDevices) { Text("Add trusted device") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
