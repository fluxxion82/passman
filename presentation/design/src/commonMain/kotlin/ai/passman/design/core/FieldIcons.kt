package ai.passman.design.core

import androidx.compose.material.icons.Icons
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
