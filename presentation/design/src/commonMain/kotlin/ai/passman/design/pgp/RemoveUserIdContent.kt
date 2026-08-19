package ai.passman.design.pgp

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.UserIdAction
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
fun RemoveUserIdContent(
    pgpKey: PgpKey,
    userId: String,
    password: String,
    action: UserIdAction,
    onPasswordChange: (String) -> Unit,
    onRemoveUser: () -> Unit,
) {
    var passwordVisible by remember { mutableStateOf(false) }
    val explanation = when (action) {
        UserIdAction.ADD -> error("not supported")
        UserIdAction.REMOVE -> "Remove $userId from key ${longToHex(pgpKey.keyId).takeLast(8)}. This ID will no longer be usable."
        UserIdAction.REVOKE -> "Revoke $userId from key ${longToHex(pgpKey.keyId).takeLast(8)}. Once revoked, this ID can no longer sign or encrypt messages. It can still decrypt previously encrypted data."
    }
    val actionLabel = when (action) {
        UserIdAction.ADD -> error("not supported")
        UserIdAction.REMOVE -> "Remove user ID"
        UserIdAction.REVOKE -> "Revoke user ID"
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(onSubmit = { onRemoveUser(); true }),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = explanation,
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
            text = actionLabel,
            onClick = onRemoveUser,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
