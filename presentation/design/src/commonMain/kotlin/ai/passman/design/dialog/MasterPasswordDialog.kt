package ai.passman.design.dialog

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

/**
 * Re-authenticates the person already using the app, before an action that hands out key material.
 *
 * The account's master password rather than an artifact's own passphrase. That is the point of it:
 * the master password is the one secret the user is certain to know, so it can gate a recovery
 * action without any risk of locking them out of a file whose own passphrase is lost, foreign, or
 * never existed.
 *
 * [error] is shown under the field and is the caller's to clear — verification happens in the
 * domain layer, so the dialog stays open on a wrong entry instead of the caller having to reopen it.
 */
@Composable
fun MasterPasswordDialog(
    title: String,
    message: String,
    error: String?,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            // Composed inside the dialog content, not on AlertDialog's modifier: the dialog is its
            // own window with its own focus owner, and on the modifier this would capture the HOST
            // screen's focus manager instead — dead Tab, focus never cleared, and an auto-repeating
            // Enter re-firing the action. Same reasoning as ExportPassphraseDialog.
            Column(
                modifier = Modifier.formKeyboardNavigation(
                    onSubmit = {
                        if (password.isNotEmpty()) {
                            onConfirm(password)
                            true
                        } else {
                            false
                        }
                    },
                ),
            ) {
                Text(text = message, style = MaterialTheme.typography.bodyMedium)
                OutlinedTextField(
                    modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                    value = password,
                    onValueChange = { password = it },
                    colors = passmanTextFieldColors(),
                    label = { Text("Master password") },
                    isError = error != null,
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        PasswordVisibilityToggle(
                            visible = passwordVisible,
                            onToggle = { passwordVisible = !passwordVisible },
                            contentDescription = "Toggle password visibility",
                        )
                    },
                    singleLine = true,
                )
                error?.let {
                    Text(
                        text = it,
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(password) },
                enabled = password.isNotEmpty(),
            ) { Text("Continue") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
