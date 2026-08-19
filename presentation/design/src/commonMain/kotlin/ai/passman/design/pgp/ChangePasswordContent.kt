package ai.passman.design.pgp

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
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
fun ChangePasswordContent(
    oldPassword: String,
    newPassword: String,
    onOldPasswordChange: (String) -> Unit,
    onNewPasswordChange: (String) -> Unit,
    onActionClicked: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var oldPasswordVisible by remember { mutableStateOf(false) }
    var newPasswordVisible by remember { mutableStateOf(false) }

    Column(
        modifier = modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(onSubmit = { onActionClicked(); true }),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = "Choose a new password for this key.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Passwords", style = MaterialTheme.typography.labelLarge)
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = oldPassword,
                onValueChange = onOldPasswordChange,
                colors = passmanTextFieldColors(),
                label = { Text("Current password") },
                placeholder = { Text("Enter the current password") },
                visualTransformation = if (oldPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = oldPasswordVisible,
                        onToggle = { oldPasswordVisible = !oldPasswordVisible },
                        contentDescription = "Toggle current password visibility",
                    )
                },
                singleLine = true,
            )
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = newPassword,
                onValueChange = onNewPasswordChange,
                colors = passmanTextFieldColors(),
                label = { Text("New password") },
                placeholder = { Text("Enter a new password") },
                visualTransformation = if (newPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = newPasswordVisible,
                        onToggle = { newPasswordVisible = !newPasswordVisible },
                        contentDescription = "Toggle new password visibility",
                    )
                },
                singleLine = true,
            )
        }

        PassmanPrimaryButton(
            text = "Change password",
            onClick = onActionClicked,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
