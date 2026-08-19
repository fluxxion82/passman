package ai.passman.design.pgp

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.SubKeyAction
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
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
fun ModifyPgpSubkeyContent(
    pgpKey: PgpKey,
    subKeyId: String,
    password: String,
    subKeyAction: SubKeyAction,
    onPasswordChange: (String) -> Unit,
    onActionClicked: () -> Unit,
) {
    var passwordVisible by remember { mutableStateOf(false) }
    val actionDescription = when (subKeyAction) {
        SubKeyAction.REMOVE -> "Remove subkey $subKeyId from ${longToHex(pgpKey.keyId).takeLast(8)}. This subkey will no longer be usable."
        SubKeyAction.REVOKE -> "Revoke subkey $subKeyId from ${longToHex(pgpKey.keyId).takeLast(8)}. This subkey will no longer be usable."
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(onSubmit = { onActionClicked(); true }),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = actionDescription,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Password", style = MaterialTheme.typography.labelLarge)
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = password,
                onValueChange = onPasswordChange,
                colors = passmanTextFieldColors(),
                label = { Text("Password") },
                placeholder = { Text("Enter the key password") },
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
        }

        PassmanPrimaryButton(
            text = "Save changes",
            onClick = onActionClicked,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
