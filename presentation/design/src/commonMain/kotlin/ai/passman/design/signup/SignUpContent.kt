package ai.passman.design.signup

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanButtonColors

import ai.passman.design.core.passmanTextFieldColors
import ai.passman.domain.user.models.PasswordStrength

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.TextField
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SignUpContent(
    userName: String,
    password: String,
    confirmPassword: String,
    passwordStrength: PasswordStrength,
    isLoading: Boolean,
    /**
     * Whether this device can do biometrics at all. Drawn only for
     * [ai.passman.domain.user.models.BiometricAvailability.Available], so a sensorless phone and
     * every desktop get a form with no checkbox rather than one that is permanently useless.
     * Defaulted off so previews and any caller without the plumbing see that same form.
     */
    biometricOfferable: Boolean = false,
    enrolBiometric: Boolean = false,
    onUsernameChange:(String) -> Unit,
    onPasswordChange:(String) -> Unit,
    onConfirmPasswordChange:(String) -> Unit,
    onSignup: () -> Unit,
    onEnrolBiometricChanged: (Boolean) -> Unit = {},
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
            // 100dp matches the welcome screen's DuelOptionContent so the title doesn't
            // jump when navigating; the back bar floats over this screen without insetting it.
            .padding(top = 100.dp)
            .formKeyboardNavigation(
                onSubmit = { if (!isLoading) { onSignup(); true } else false },
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        var passwordVisibility by remember { mutableStateOf(false) }

        Text(
            modifier = Modifier,
            text = "PassMan", // stringResource(id = R.string.app_name),
            color = MaterialTheme.colorScheme.onPrimary,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
        )

        TextField(
            modifier = Modifier
                .padding(0.dp, 50.dp, 0.dp, 0.dp),
            value = userName,
            onValueChange = onUsernameChange,
            colors = passmanTextFieldColors(),
            label = { Text("Username", color = MaterialTheme.colorScheme.onSurface) }, // stringResource(R.string.username_hint)
            singleLine = true,
        )

        TextField(
            modifier = Modifier
                .padding(0.dp, 10.dp, 0.dp, 0.dp)
                .background(MaterialTheme.colorScheme.surface),
            value = password,
            onValueChange = onPasswordChange,
            colors = passmanTextFieldColors(),
            visualTransformation = if (passwordVisibility) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                PasswordVisibilityToggle(
                    visible = passwordVisibility,
                    onToggle = { passwordVisibility = !passwordVisibility },
                    contentDescription = "password visibility",
                )
            },
            label = { Text("Password", color = MaterialTheme.colorScheme.onSurface) }, // stringResource(R.string.password_hint)
            singleLine = true,
        )

        if (password.isNotEmpty()) {
            PasswordStrengthMeter(
                strength = passwordStrength,
                modifier = Modifier
                    .width(280.dp)
                    .padding(top = 8.dp),
            )
        }

        TextField(
            modifier = Modifier
                .padding(0.dp, 10.dp, 0.dp, 0.dp)
                .background(MaterialTheme.colorScheme.surface),
            value = confirmPassword,
            onValueChange = onConfirmPasswordChange,
            colors = passmanTextFieldColors(),
            visualTransformation = if (passwordVisibility) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            isError = confirmPassword.isNotEmpty() && confirmPassword != password,
            label = { Text("Confirm password", color = MaterialTheme.colorScheme.onSurface) },
            singleLine = true,
        )

        if (biometricOfferable) {
            // Asked here, on the form, rather than as a modal after the account is made: it is one
            // more decision while the user is already making decisions, and it costs a tap instead
            // of a dialog. Nothing acts on it until signup succeeds — the enrolment must not land
            // inside the account bootstrap's rollback contract.
            Row(
                modifier = Modifier
                    .width(280.dp)
                    .padding(top = 12.dp)
                    .toggleable(
                        value = enrolBiometric,
                        enabled = !isLoading,
                        role = Role.Checkbox,
                        onValueChange = onEnrolBiometricChanged,
                    ),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // The backdrop is the primary blue, so the stock primary-tinted box would vanish
                // into it. onPrimary is the readable role here in both schemes (9.90:1 on #00BFFF),
                // with the checkmark punched back out in primary.
                Checkbox(
                    checked = enrolBiometric,
                    // null: the whole Row is the toggle target, and a second one here would make
                    // the box unreachable by the row's own click.
                    onCheckedChange = null,
                    enabled = !isLoading,
                    colors = CheckboxDefaults.colors(
                        checkedColor = MaterialTheme.colorScheme.onPrimary,
                        uncheckedColor = MaterialTheme.colorScheme.onPrimary,
                        checkmarkColor = MaterialTheme.colorScheme.primary,
                    ),
                )
                Icon(
                    imageVector = Icons.Filled.Fingerprint,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onPrimary,
                    modifier = Modifier.padding(end = 8.dp),
                )
                Text(
                    text = "Unlock with your fingerprint",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            }
        }

        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier
                    .wrapContentSize()
                    .padding(start = 50.dp, top = 50.dp, end = 50.dp),
                // The screen root is primary; the spinner's default primary color vanishes on it.
                color = MaterialTheme.colorScheme.onPrimary,
            )
        } else {
            val focusManager = LocalFocusManager.current
            Button(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 50.dp, top = 50.dp, end = 50.dp)
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(bounded = false),
                        onClick = {}
                    ),
                shape = RoundedCornerShape(80),
                colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
                onClick = {
                    focusManager.clearFocus()
                    onSignup()
                }
            ) {
                Text(
                    text = "Sign Up", // stringResource(R.string.signup)
                    fontSize = 18.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
private fun PasswordStrengthMeter(
    strength: PasswordStrength,
    modifier: Modifier = Modifier,
) {
    // Fixed colors rather than scheme roles: the meter is a traffic light and has to read the
    // same on the primary-colored signup background in both themes.
    val (fraction, color, label) = when (strength) {
        PasswordStrength.Weak -> Triple(0.25f, Color(0xFFE57373), "Weak")
        PasswordStrength.Fair -> Triple(0.5f, Color(0xFFFFB74D), "Fair")
        PasswordStrength.Good -> Triple(0.75f, Color(0xFF9CCC65), "Good")
        PasswordStrength.Strong -> Triple(1f, Color(0xFF66BB6A), "Strong")
    }
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        LinearProgressIndicator(
            progress = { fraction },
            modifier = Modifier.weight(1f),
            color = color,
            trackColor = MaterialTheme.colorScheme.onPrimary.copy(alpha = 0.2f),
        )
        Text(
            modifier = Modifier.padding(start = 8.dp),
            text = label,
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onPrimary,
        )
    }
}
