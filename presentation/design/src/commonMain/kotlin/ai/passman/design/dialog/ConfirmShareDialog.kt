package ai.passman.design.dialog

import ai.passman.domain.settings.model.ShareFileKind
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Confirmation shown before any file leaves the app: names the exact file and states what it
 * contains, with warning wording whenever private key material is involved.
 */
@Composable
fun ConfirmShareDialog(
    fileName: String,
    kind: ShareFileKind,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    detail: String? = null,
) {
    val title: String
    val message: String
    val confirmLabel: String
    when (kind) {
        ShareFileKind.PublicKeyOnly -> {
            title = "Share public key?"
            message = "\"$fileName\" contains the public key only — no private key material."
            confirmLabel = "Share"
        }
        ShareFileKind.EntireKeystore -> {
            title = "Share keystore file?"
            message = "\"$fileName\" is the entire keystore. This file contains private keys. " +
                "Only share it with a destination you trust."
            confirmLabel = "Share"
        }
        ShareFileKind.PrivateKey -> {
            title = "Export private key?"
            message = "\"$fileName\" contains your PRIVATE key ring. It stays encrypted with " +
                "its passphrase. Only export it to a destination you trust."
            confirmLabel = "Export"
        }
        ShareFileKind.DisplacedVersion -> {
            // Deliberately claims less than the others. Nothing in the conflict store distinguishes
            // a secret ring from a public one or from a whole keystore, so promising that this file
            // is passphrase-protected could be false in the one direction that harms the user.
            title = "Export this version?"
            message = "\"$fileName\" is a version an incoming sync replaced. It may be a private " +
                "key ring or an entire keystore — Passman cannot tell which, so treat it as " +
                "private key material and only export it to a destination you trust."
            confirmLabel = "Export"
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(message)
                detail?.let {
                    Text(
                        text = it,
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                if (kind == ShareFileKind.PublicKeyOnly) {
                    Text(confirmLabel)
                } else {
                    // Private key material leaves the app: error-colored confirm, matching the
                    // destructive-action convention in ConfirmDeleteDialog.
                    Text(confirmLabel, color = MaterialTheme.colorScheme.error)
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
