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

@Composable
fun EnterPassword(
    keystorePath: String,
    password: String,
    onPasswordChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onButtonClicked: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var passwordVisible by remember { mutableStateOf(false) }
    val keystoreFileName = keystorePath
        .substringAfterLast('/')
        .substringAfterLast('\\')

    AlertDialog(
        modifier = modifier,
        onDismissRequest = onDismiss,
        title = { Text("Unlock keystore") },
        text = {
            // The dialog is its own window with its own focus owner, so the handler must be
            // composed here, inside the dialog content — on the AlertDialog's modifier param it
            // would capture the HOST screen's focus manager (dead Tab, focus never cleared,
            // auto-repeat Enter re-firing the unlock). Gated the same way as the Unlock button.
            Column(
                modifier = Modifier.formKeyboardNavigation(
                    onSubmit = {
                        if (password.isNotEmpty()) {
                            onButtonClicked()
                            true
                        } else {
                            false
                        }
                    },
                ),
            ) {
                Text(
                    text = "Keystore: $keystoreFileName",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 16.dp),
                    value = password,
                    onValueChange = onPasswordChange,
                    colors = passmanTextFieldColors(),
                    label = { Text("Keystore password") },
                    placeholder = { Text("Enter the keystore password") },
                    visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        PasswordVisibilityToggle(
                            visible = passwordVisible,
                            onToggle = { passwordVisible = !passwordVisible },
                            contentDescription = "Toggle keystore password visibility",
                        )
                    },
                    singleLine = true,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = onButtonClicked,
                enabled = password.isNotEmpty(),
            ) { Text("Unlock") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
