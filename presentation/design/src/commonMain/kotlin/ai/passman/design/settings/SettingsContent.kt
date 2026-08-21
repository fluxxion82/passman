package ai.passman.design.settings

import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.model.PortableVaultRecoveryFormat
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.formKeyboardNavigation
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.TextField
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

@Composable
fun SettingsContent(
    changePassIcon: Painter,
    transferIcon: Painter,
    manageDevicesIcon: Painter,
    syncActivityIcon: Painter,
    replacedBySyncIcon: Painter,
    privacyIcon: Painter,
    clipboardIcon: Painter,
    biometricIcon: Painter,
    themeIcon: Painter,
    oldPassword: String,
    newPassword: String,
    changePasswordDialogVisible: Boolean,
    isChangingPassword: Boolean,
    changePasswordError: String?,
    clipboardExpiryEnabled: Boolean,
    clipboardExpirySeconds: Long,
    biometricUnlock: BiometricUnlockState,
    biometricPasswordDialogVisible: Boolean,
    biometricPassword: String,
    isEnrollingBiometric: Boolean,
    biometricUnlockError: String?,
    themeMode: ThemeMode,
    appVersion: String,
    onOldPassUpdated: (String) -> Unit,
    onNewPassUpdated: (String) -> Unit,
    onChangePasswordDialogOpened: () -> Unit,
    onChangePasswordDialogDismissed: () -> Unit,
    onChangePasswordClicked: () -> Unit,
    onTransferClick: () -> Unit,
    onManageDevicesClick: () -> Unit,
    onSyncActivityClick: () -> Unit,
    onReplacedBySyncClick: () -> Unit,
    onPrivacyPolicyClick: () -> Unit,
    onClipboardExpiryToggled: (Boolean) -> Unit,
    onBiometricUnlockToggled: (Boolean) -> Unit,
    onBiometricPasswordChanged: (String) -> Unit,
    onBiometricDialogDismissed: () -> Unit,
    onBiometricEnrollConfirmed: () -> Unit,
    onThemeModeSelected: (ThemeMode) -> Unit,
    portableVaultAccess: PortableVaultAccess?,
    portableVaultDialogVisible: Boolean,
    onPortableVaultAccessClick: () -> Unit,
    onPortableVaultDialogDismissed: () -> Unit,
    onPortableVaultRecoveryCopyClicked: () -> Unit,
    onPortableVaultRecoveryUpgradeClicked: () -> Unit,
) {
    Column(
        modifier = Modifier
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        SettingsTextWithDialog(
            name = "Change User Password",
            oldPassword = oldPassword,
            newPassword = newPassword,
            isDialogShown = changePasswordDialogVisible,
            isChangingPassword = isChangingPassword,
            errorMessage = changePasswordError,
            onOldPassUpdated = onOldPassUpdated,
            onNewPassUpdated = onNewPassUpdated,
            onOpen = onChangePasswordDialogOpened,
            onDismiss = onChangePasswordDialogDismissed,
            onSave = {
                onChangePasswordClicked()
            },
            icon = changePassIcon,
        )

        SettingsText(
            icon = transferIcon,
            name = "Transfer Passwords",
            onClick = onTransferClick,
        )

        SettingsText(
            icon = changePassIcon,
            name = "Portable Vault Recovery",
            onClick = onPortableVaultAccessClick,
        )

        SettingsText(
            icon = manageDevicesIcon,
            name = "Manage Paired Devices",
            onClick = onManageDevicesClick,
        )

        SettingsText(
            icon = syncActivityIcon,
            name = "Sync Activity",
            onClick = onSyncActivityClick,
        )

        SettingsText(
            icon = replacedBySyncIcon,
            name = "Replaced by Sync",
            onClick = onReplacedBySyncClick,
        )

        SettingsText(
            icon = privacyIcon,
            name = "Privacy Policy",
            onClick = onPrivacyPolicyClick,
        )

        SettingsSwitch(
            icon = clipboardIcon,
            name = "Clear Copied Passwords",
            summary = "Takes a copied password back off the clipboard after $clipboardExpirySeconds seconds. " +
                "Anything you copy afterwards is left alone.",
            checked = clipboardExpiryEnabled,
            onCheckedChange = onClipboardExpiryToggled,
        )

        // Hidden outright on hardware that has no sensor — see BiometricUnlockState.offerable. Every
        // other state leaves the row up, because every other state is something the user can fix.
        if (biometricUnlock.offerable) {
            SettingsSwitch(
                icon = biometricIcon,
                name = "Biometric unlock",
                summary = biometricUnlockSummary(biometricUnlock),
                checked = biometricUnlock.enrolled,
                onCheckedChange = onBiometricUnlockToggled,
            )
        }

        SettingsSegmented(
            icon = themeIcon,
            name = "Theme",
            summary = "Choose whether Passman follows your device or stays light or dark.",
            selectedMode = themeMode,
            onModeSelected = onThemeModeSelected,
            // Last row: no trailing divider. Move this flag if a row is ever appended below. The
            // build line under it is not a row — it takes no divider and is not tappable.
            showDivider = false,
        )

        AppVersionLabel(appVersion)

        if (biometricPasswordDialogVisible) {
            Dialog(
                onDismissRequest = { if (!isEnrollingBiometric) onBiometricDialogDismissed() },
                properties = DialogProperties(
                    dismissOnBackPress = !isEnrollingBiometric,
                    dismissOnClickOutside = !isEnrollingBiometric,
                ),
            ) {
                BiometricEnrolDialog(
                    password = biometricPassword,
                    isEnrolling = isEnrollingBiometric,
                    errorMessage = biometricUnlockError,
                    onPasswordChanged = onBiometricPasswordChanged,
                    onConfirm = onBiometricEnrollConfirmed,
                )
            }
        }

        if (portableVaultDialogVisible && portableVaultAccess != null) {
            PortableVaultAccessDialog(
                access = portableVaultAccess,
                onDismiss = onPortableVaultDialogDismissed,
                onCopy = onPortableVaultRecoveryCopyClicked,
                onUpgrade = onPortableVaultRecoveryUpgradeClicked,
            )
        }
    }
}

/**
 * The build identity, centred under the last setting.
 *
 * It rides at the end of the same scrolling column rather than being pinned to the window, because
 * the settings list is already taller than every screen it renders on — a pinned line would sit on
 * top of the rows instead of after them.
 *
 * Blank while the read is in flight, and blank means nothing is drawn: no reserved gap that shifts
 * the list a frame later.
 */
@Composable
private fun AppVersionLabel(appVersion: String) {
    if (appVersion.isBlank()) return

    Text(
        text = appVersion,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp, bottom = 24.dp),
    )
}

/**
 * What the row says under its title, which is the only place the user learns *why* the switch is
 * refusing them. "Off" and "off because you deleted your fingerprints" look identical otherwise.
 */
private fun biometricUnlockSummary(state: BiometricUnlockState): String = when {
    state.availability == BiometricAvailability.NotEnrolled ->
        "Register a fingerprint or face on this device to use it here."
    state.availability != BiometricAvailability.Available ->
        "Your biometric sensor is unavailable right now."
    state.enrolled ->
        "Your master password is sealed in this device's hardware and released by your biometric. " +
            "Changing your master password, or the biometrics registered on this device, turns it back off."
    else ->
        "Unlock without typing your master password. You will be asked for it once, to seal a copy " +
            "in this device's hardware."
}

/**
 * A single password field. It is asking for the master password again on a screen that is already
 * inside an unlocked session, which looks redundant and is not: this is the one action that makes a
 * *second* copy of that password, so it happens only at a moment the user has proved they know it.
 *
 * Blocks on [isEnrolling] exactly like the change-password dialog, and for the same reason — the
 * system prompt is up, and walking away from this screen kills the ViewModel running it.
 */
@Composable
private fun BiometricEnrolDialog(
    password: String,
    isEnrolling: Boolean,
    errorMessage: String?,
    onPasswordChanged: (String) -> Unit,
    onConfirm: () -> Unit,
) {
    var passwordVisible by remember { mutableStateOf(false) }

    Surface(
        color = MaterialTheme.colorScheme.primary,
        contentColor = MaterialTheme.colorScheme.onPrimary,
        // Composed inside the Dialog content lambda so it captures the DIALOG's focus manager.
        modifier = Modifier.formKeyboardNavigation(
            onSubmit = {
                if (!isEnrolling) {
                    onConfirm()
                    true
                } else {
                    false
                }
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .wrapContentHeight()
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Text("Turn on biometric unlock")
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Confirm your master password. It is sealed under a key this device's " +
                    "hardware will only release after your biometric matches.",
                style = MaterialTheme.typography.bodySmall,
            )
            Spacer(modifier = Modifier.height(8.dp))
            TextField(
                password,
                enabled = !isEnrolling,
                label = { Text("Master password", color = MaterialTheme.colorScheme.onSurface) },
                singleLine = true,
                visualTransformation = if (passwordVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = passwordVisible,
                        onToggle = { passwordVisible = !passwordVisible },
                        contentDescription = "Toggle master password visibility",
                    )
                },
                onValueChange = onPasswordChanged,
            )

            if (errorMessage != null && !isEnrolling) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = errorMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Row {
                Spacer(modifier = Modifier.weight(1f))
                PassmanPrimaryButton(
                    enabled = !isEnrolling,
                    onClick = onConfirm,
                ) {
                    if (isEnrolling) {
                        CircularProgressIndicator(
                            modifier = Modifier.padding(end = 8.dp),
                            color = MaterialTheme.colorScheme.onSurface,
                            strokeWidth = 2.dp,
                        )
                    }
                    Text("Turn on", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
private fun PortableVaultAccessDialog(
    access: PortableVaultAccess,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onUpgrade: () -> Unit,
) {
    val legacy = access.recoveryFormat == PortableVaultRecoveryFormat.LegacyBase64Url
    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = MaterialTheme.shapes.large) {
            Column(modifier = Modifier.padding(24.dp)) {
                Text("Portable Vault Recovery", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(12.dp))
                Text(
                    if (legacy) {
                        "Save this legacy recovery password outside Passman. It opens the recovery P12 for command-line access."
                    } else {
                        "Save this 24-word recovery phrase outside Passman. It is the password for the recovery P12 and opens it with standard command-line tools."
                    },
                )
                Spacer(Modifier.height(12.dp))
                Text(access.recoveryPassword, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(12.dp))
                PassmanPrimaryButton(
                    text = if (legacy) "Copy recovery password" else "Copy recovery phrase",
                    onClick = onCopy,
                )
                if (legacy) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "Upgrade to a 24-word phrase to make the recovery secret easier to record. " +
                            "The old recovery password will stop opening this P12.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Spacer(Modifier.height(8.dp))
                    PassmanPrimaryButton(text = "Upgrade to 24-word phrase", onClick = onUpgrade)
                }
                Spacer(Modifier.height(12.dp))
                Text("P12: ${access.pkcs12Path}", style = MaterialTheme.typography.bodySmall)
                Text("Certificate: ${access.certificatePath}", style = MaterialTheme.typography.bodySmall)
                Text("Vault: ${access.vaultPath}", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(16.dp))
                PassmanPrimaryButton(text = "Done", onClick = onDismiss, modifier = Modifier.align(Alignment.End))
            }
        }
    }
}

@Composable
fun SettingsSwitch(
    icon: Painter,
    name: String,
    summary: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
    showDivider: Boolean = true,
) {
    Surface(
        color = Color.Transparent,
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
    ) {
        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Icon(
                    icon,
                    contentDescription = "icon",
                    modifier = Modifier.size(24.dp),
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f).padding(8.dp)) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Start,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = summary,
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Start,
                    )
                }
                Switch(
                    checked = checked,
                    onCheckedChange = onCheckedChange,
                )
            }
            if (showDivider) HorizontalDivider()
        }
    }
}

@Composable
fun SettingsSegmented(
    icon: Painter,
    name: String,
    summary: String,
    selectedMode: ThemeMode,
    onModeSelected: (ThemeMode) -> Unit,
    showDivider: Boolean = true,
) {
    val modes = listOf(ThemeMode.System, ThemeMode.Light, ThemeMode.Dark)

    Surface(
        color = Color.Transparent,
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = "icon",
                    modifier = Modifier.size(24.dp),
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f).padding(8.dp)) {
                    Text(
                        text = name,
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Start,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = summary,
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Start,
                    )
                }
            }
            SingleChoiceSegmentedButtonRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
            ) {
                modes.forEachIndexed { index, mode ->
                    SegmentedButton(
                        selected = selectedMode == mode,
                        onClick = { onModeSelected(mode) },
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = modes.size),
                        label = { Text(themeModeLabel(mode)) },
                    )
                }
            }
            if (showDivider) HorizontalDivider()
        }
    }
}

private fun themeModeLabel(mode: ThemeMode): String = when (mode) {
    ThemeMode.System -> "System"
    ThemeMode.Light -> "Light"
    ThemeMode.Dark -> "Dark"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsText(
    icon: Painter,
    name: String,
    onClick: () -> Unit,
    showDivider: Boolean = true,
) {
    Surface(
        color = Color.Transparent,
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        onClick = onClick,
    ) {
        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Icon(
                    icon,
                    contentDescription = "icon",
                    modifier = Modifier
                        .size(24.dp)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    modifier = Modifier.padding(8.dp),
                    text = name,
                    style = MaterialTheme.typography.bodyLarge,
                    textAlign = TextAlign.Start,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (showDivider) HorizontalDivider()
        }
    }
}

/**
 * [isDialogShown] is hoisted rather than remembered here because closing it is an outcome of the
 * change, not of the tap that dismissed it: while [isChangingPassword] is set the dialog refuses
 * every way out — the scrim, the back button and the save button all — because navigating away is
 * what kills the ViewModel running the change, and a master-password change that is cancelled
 * halfway is silently discarded.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsTextWithDialog(
    icon: Painter,
    name: String,
    oldPassword: String,
    newPassword: String,
    isDialogShown: Boolean,
    isChangingPassword: Boolean,
    errorMessage: String?,
    onOldPassUpdated: (String) -> Unit,
    onNewPassUpdated: (String) -> Unit,
    onOpen: () -> Unit,
    onDismiss: () -> Unit,
    onSave: () -> Unit,
    showDivider: Boolean = true,
) {
    // todo move dialog to app nav graph
    if (isDialogShown) {
        Dialog(
            onDismissRequest = {
                if (!isChangingPassword) onDismiss()
            },
            properties = DialogProperties(
                dismissOnBackPress = !isChangingPassword,
                dismissOnClickOutside = !isChangingPassword,
            ),
        ) {
            TextEditDialog(
                name = name,
                oldPassword = oldPassword,
                newPassword = newPassword,
                isChangingPassword = isChangingPassword,
                errorMessage = errorMessage,
                onOldPassUpdated = onOldPassUpdated,
                onNewPassUpdated = onNewPassUpdated,
                onSave = onSave,
            )
        }
    }

    Surface(
        color = Color.Transparent,
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        onClick = onOpen,
    ) {
        Column {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Start
            ) {
                Icon(
                    icon,
                    contentDescription = "settings text icon",
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Text(
                    modifier = Modifier.padding(8.dp),
                    text = name,
                    style = MaterialTheme.typography.bodyLarge,
                    textAlign = TextAlign.Start,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (showDivider) HorizontalDivider()
        }
    }
}

@Composable
private fun TextEditDialog(
    name: String,
    oldPassword: String,
    newPassword: String,
    isChangingPassword: Boolean,
    errorMessage: String?,
    onOldPassUpdated: (String) -> Unit,
    onNewPassUpdated: (String) -> Unit,
    onSave: () -> Unit,
) {
    var oldPasswordVisible by remember { mutableStateOf(false) }
    var newPasswordVisible by remember { mutableStateOf(false) }

    Surface(
        color = MaterialTheme.colorScheme.primary,
        contentColor = MaterialTheme.colorScheme.onPrimary,
        // The dialog is its own window with its own focus owner; this handler is composed here,
        // inside the Dialog content lambda, so it captures the DIALOG's focus manager — it must
        // never move to the Dialog call's parameters in the host composition. Gated like the
        // Next button.
        modifier = Modifier.formKeyboardNavigation(
            onSubmit = {
                if (!isChangingPassword) {
                    onSave()
                    true
                } else {
                    false
                }
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .wrapContentHeight()
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Text(name)
            Spacer(modifier = Modifier.height(8.dp))
            TextField(
                oldPassword,
                enabled = !isChangingPassword,
                label = { Text("Old Password", color = MaterialTheme.colorScheme.onSurface) },
                singleLine = true,
                visualTransformation = if (oldPasswordVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = oldPasswordVisible,
                        onToggle = { oldPasswordVisible = !oldPasswordVisible },
                        contentDescription = "Toggle old password visibility",
                    )
                },
                onValueChange = {
                onOldPassUpdated(it)
            })

            Spacer(modifier = Modifier.height(8.dp))

            TextField(
                newPassword,
                enabled = !isChangingPassword,
                label = { Text("New Password", color = MaterialTheme.colorScheme.onSurface) },
                singleLine = true,
                visualTransformation = if (newPasswordVisible) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = newPasswordVisible,
                        onToggle = { newPasswordVisible = !newPasswordVisible },
                        contentDescription = "Toggle new password visibility",
                    )
                },
                onValueChange = {
                onNewPassUpdated(it)
            })

            if (isChangingPassword) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Changing your master password. This takes a few seconds — please keep " +
                        "this screen open until it finishes.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (errorMessage != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = errorMessage,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            Row {
                Spacer(modifier = Modifier.weight(1f))
                PassmanPrimaryButton(
                    enabled = !isChangingPassword,
                    // The dialog is dismissed by the outcome, never by the click: a change that
                    // fails has to stay on screen, and a change still running must not be walked
                    // away from.
                    onClick = onSave,
                ) {
                    if (isChangingPassword) {
                        CircularProgressIndicator(
                            modifier = Modifier.padding(end = 8.dp),
                            // The spinner only shows while the button is disabled, so it sits on
                            // the 12%-alpha disabled fill, not primary: onSurface, not onPrimary.
                            color = MaterialTheme.colorScheme.onSurface,
                            strokeWidth = 2.dp,
                        )
                    }
                    Text("Next", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}
