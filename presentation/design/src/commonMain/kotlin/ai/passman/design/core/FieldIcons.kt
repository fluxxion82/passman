package ai.passman.design.core

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusProperties

/**
 * Trailing eye icon for password fields. Deliberately excluded from focus traversal: Tab through a
 * form should step field → field → primary button, not stop on every decorative trailing icon.
 * Mouse and touch still reach it.
 */
@Composable
fun PasswordVisibilityToggle(
    visible: Boolean,
    onToggle: () -> Unit,
    contentDescription: String = "password visibility",
) {
    IconButton(
        onClick = onToggle,
        modifier = Modifier.focusProperties { canFocus = false },
    ) {
        Icon(
            imageVector = if (visible) Icons.Filled.Visibility else Icons.Filled.VisibilityOff,
            contentDescription = contentDescription,
        )
    }
}

/**
 * Trailing fingerprint icon that signs the account in from its biometric enrolment.
 *
 * Only ever drawn for an account that *has* an enrolment this device can use, so it is an action
 * and never an invitation to switch the feature on: enabling it seals a copy of the master
 * password, which may only happen once the password has been verified, and verifying a typed
 * password on the login screen without signing anybody in is an oracle
 * (see `LocalUserRepository.enable`).
 *
 * [Icons.Filled.Fingerprint] is the same icon the settings row draws for biometric unlock, so the
 * thing the user turned on there and the thing they tap here look like one feature.
 *
 * Skipped by Tab traversal for the same reason as [PasswordVisibilityToggle].
 */
@Composable
fun BiometricUnlockAction(
    onClick: () -> Unit,
    contentDescription: String = "unlock with biometrics",
) {
    IconButton(
        onClick = onClick,
        modifier = Modifier.focusProperties { canFocus = false },
    ) {
        Icon(imageVector = Icons.Filled.Fingerprint, contentDescription = contentDescription)
    }
}

/**
 * Trailing refresh icon that regenerates a suggested password. Skipped by Tab traversal for the
 * same reason as [PasswordVisibilityToggle].
 */
@Composable
fun RegeneratePasswordButton(
    onClick: () -> Unit,
    contentDescription: String = "generate new password",
) {
    IconButton(
        onClick = onClick,
        modifier = Modifier.focusProperties { canFocus = false },
    ) {
        Icon(imageVector = Icons.Filled.Refresh, contentDescription = contentDescription)
    }
}
