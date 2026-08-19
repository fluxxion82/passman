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
 * Passphrase prompt for the guarded private-key export. The passphrase is verified downstream by
 * an actual secret-key unlock attempt; this dialog only collects it.
 */
@Composable
fun ExportPassphraseDialog(
    keyName: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var passphrase by remember { mutableStateOf("") }
    var passphraseVisible by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Export private key") },
        text = {
            // The dialog is its own window with its own focus owner, so the handler must be
            // composed here, inside the dialog content — on the AlertDialog's modifier param it
            // would capture the HOST screen's focus manager (dead Tab, focus never cleared,
            // auto-repeat Enter re-firing the export). Gated the same way as the Continue button.
            Column(
                modifier = Modifier.formKeyboardNavigation(
                    onSubmit = {
                        if (passphrase.isNotEmpty()) {
                            onConfirm(passphrase)
                            true
                        } else {
                            false
                        }
                    },
                ),
            ) {
                Text(
                    text = "Enter the passphrase for \"$keyName\" to export its secret key ring. " +
                        "The exported file stays encrypted with this passphrase.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    colors = passmanTextFieldColors(),
                    label = { Text("Key passphrase") },
                    visualTransformation = if (passphraseVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        PasswordVisibilityToggle(
                            visible = passphraseVisible,
                            onToggle = { passphraseVisible = !passphraseVisible },
                            contentDescription = "Toggle passphrase visibility",
                        )
                    },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(passphrase) },
                enabled = passphrase.isNotEmpty(),
            ) { Text("Continue") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
