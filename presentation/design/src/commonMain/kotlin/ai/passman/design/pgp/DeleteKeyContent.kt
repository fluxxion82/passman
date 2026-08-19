package ai.passman.design.pgp

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
fun DeleteKeyContent(
    isError: Boolean,
    errorMessage: String,
    onConfirmDeleteClick: () -> Unit,
    onCancelClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (isError || errorMessage.isNotBlank()) {
        AlertDialog(
            modifier = modifier,
            onDismissRequest = onCancelClick,
            title = { Text("Couldn't delete key") },
            text = { Text(errorMessage) },
            confirmButton = {
                TextButton(onClick = onCancelClick) { Text("Close") }
            },
        )
    } else {
        AlertDialog(
            modifier = modifier,
            onDismissRequest = onCancelClick,
            title = { Text("Delete key pair?") },
            text = {
                Text("This deletes the public and secret key. Data encrypted to this key can no longer be decrypted.")
            },
            confirmButton = {
                TextButton(onClick = onConfirmDeleteClick) {
                    Text("Delete key", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = onCancelClick) { Text("Cancel") }
            },
        )
    }
}
