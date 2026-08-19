package ai.passman.design.keystore

import ai.passman.design.core.DropdownField
import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.design.mapper.toAllowedKeyAlgos
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

@Composable
fun AddKeystoreKeyContent(
    keyStoreType: KeyStoreType,
    keyStoreName: String,
    keyAlias: String,
    keyAlgorithm: KeystoreKeyAlgorithm,
    keyPassword: String,
    keyStorePassword: String,
    isSavePassToListChecked: Boolean,
    isLoading: Boolean,
    onKeyAliasChanged: (String) -> Unit,
    onKeyAlgorithmPicked: (KeystoreKeyAlgorithm) -> Unit,
    onKeyPasswordChanged: (String) -> Unit,
    onKeyStorePasswordChange: (String) -> Unit,
    onAddClicked: () -> Unit,
    onReGenPass: () -> Unit,
    onSavePasswordChecked: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    var keyPasswordVisible by remember { mutableStateOf(false) }
    var keyStorePasswordVisible by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(onSubmit = { onAddClicked(); true }),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = "Add a key to $keyStoreName.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Identity", style = MaterialTheme.typography.labelLarge)
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = keyAlias,
                onValueChange = onKeyAliasChanged,
                colors = passmanTextFieldColors(),
                label = { Text("Key alias") },
                placeholder = { Text("Enter an alias for this key") },
                singleLine = true,
            )
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Key options", style = MaterialTheme.typography.labelLarge)
            DropdownField(
                modifier = Modifier.fillMaxWidth(),
                items = keyStoreType.toAllowedKeyAlgos().map { it.name },
                label = "Key algorithm",
                value = keyAlgorithm.name,
                enabled = true,
                onItemSelected = { _, algorithmName ->
                    onKeyAlgorithmPicked(KeystoreKeyAlgorithm.valueOf(algorithmName))
                },
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = isSavePassToListChecked,
                    onCheckedChange = onSavePasswordChecked,
                )
                Text("Save the key password to the password list", style = MaterialTheme.typography.bodyMedium)
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Passwords", style = MaterialTheme.typography.labelLarge)
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = keyPassword,
                onValueChange = onKeyPasswordChanged,
                colors = passmanTextFieldColors(),
                label = { Text("Key password") },
                placeholder = { Text("Enter or generate a key password") },
                visualTransformation = if (keyPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    Row {
                        RegeneratePasswordButton(
                            onClick = onReGenPass,
                            contentDescription = "Generate a new password",
                        )
                        PasswordVisibilityToggle(
                            visible = keyPasswordVisible,
                            onToggle = { keyPasswordVisible = !keyPasswordVisible },
                            contentDescription = "Toggle key password visibility",
                        )
                    }
                },
                singleLine = true,
            )
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = keyStorePassword,
                onValueChange = onKeyStorePasswordChange,
                colors = passmanTextFieldColors(),
                label = { Text("Keystore password") },
                placeholder = { Text("Enter the keystore password") },
                visualTransformation = if (keyStorePasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = keyStorePasswordVisible,
                        onToggle = { keyStorePasswordVisible = !keyStorePasswordVisible },
                        contentDescription = "Toggle keystore password visibility",
                    )
                },
                singleLine = true,
            )
        }

        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier.align(Alignment.CenterHorizontally),
            )
        } else {
            PassmanPrimaryButton(
                text = "Add key",
                onClick = onAddClicked,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
