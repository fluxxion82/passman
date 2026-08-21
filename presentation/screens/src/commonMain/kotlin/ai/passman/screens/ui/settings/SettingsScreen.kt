package ai.passman.screens.ui.settings

import ai.passman.design.settings.SettingsContent
import ai.passman.screens.ui.PreservedCopiesRoute
import ai.passman.screens.ui.SyncActivityRoute
import ai.passman.screens.ui.TransferPasswords
import ai.passman.screens.ui.TrustedDevicesRoute
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.viewvo.navigation.SettingsNavigation
import ai.passman.viewmodel.settings.SettingsViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChangeHistory
import androidx.compose.material.icons.filled.Brightness6
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.ImportExport
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Security
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun SettingsScreen(
    navController: NavController,
    presenter: SettingsViewModel,
    snackbarHostState: SnackbarHostState,
    onThemeModeChanged: (ThemeMode) -> Unit,
) {
    val uriHandler = LocalUriHandler.current
    val scope = rememberCoroutineScope()
    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is SettingsNavigation.Transfer ->
                    navController.navigate(TransferPasswords)
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val oldPass by presenter.oldPassword.collectAsState()
    val newPass by presenter.newPassword.collectAsState()
    val changePasswordDialogVisible by presenter.changePasswordDialogVisible.collectAsState()
    val isChangingPassword by presenter.isChangingPassword.collectAsState()
    val changePasswordError by presenter.changePasswordError.collectAsState()
    val clipboardExpiryEnabled by presenter.clipboardExpiryEnabled.collectAsState()
    val clipboardExpirySeconds by presenter.clipboardExpirySeconds.collectAsState()
    val themeMode by presenter.themeMode.collectAsState()
    val portableVaultAccess by presenter.portableVaultAccess.collectAsState()
    val portableVaultDialogVisible by presenter.portableVaultDialogVisible.collectAsState()
    val biometricUnlock by presenter.biometricUnlock.collectAsState()
    val biometricPasswordDialogVisible by presenter.biometricPasswordDialogVisible.collectAsState()
    val biometricPassword by presenter.biometricPassword.collectAsState()
    val isEnrollingBiometric by presenter.isEnrollingBiometric.collectAsState()
    val biometricUnlockError by presenter.biometricUnlockError.collectAsState()
    val appVersion by presenter.appVersion.collectAsState()

    SettingsContent(
        oldPassword = oldPass,
        newPassword = newPass,
        changePasswordDialogVisible = changePasswordDialogVisible,
        isChangingPassword = isChangingPassword,
        changePasswordError = changePasswordError,
        clipboardExpiryEnabled = clipboardExpiryEnabled,
        clipboardExpirySeconds = clipboardExpirySeconds,
        biometricUnlock = biometricUnlock,
        biometricPasswordDialogVisible = biometricPasswordDialogVisible,
        biometricPassword = biometricPassword,
        isEnrollingBiometric = isEnrollingBiometric,
        biometricUnlockError = biometricUnlockError,
        appVersion = appVersion,
        onOldPassUpdated = presenter::onOldPasswordChanged,
        onNewPassUpdated = presenter::onNewPasswordChanged,
        onChangePasswordDialogOpened = presenter::onChangePasswordDialogOpened,
        onChangePasswordDialogDismissed = presenter::onChangePasswordDialogDismissed,
        changePassIcon = rememberVectorPainter(image = Icons.Filled.ChangeHistory),
        transferIcon = rememberVectorPainter(image = Icons.Filled.ImportExport),
        manageDevicesIcon = rememberVectorPainter(image = Icons.Filled.Devices),
        syncActivityIcon = rememberVectorPainter(image = Icons.Filled.History),
        replacedBySyncIcon = rememberVectorPainter(image = Icons.Filled.Restore),
        privacyIcon = rememberVectorPainter(image = Icons.Filled.Security),
        clipboardIcon = rememberVectorPainter(image = Icons.Filled.ContentPaste),
        biometricIcon = rememberVectorPainter(image = Icons.Filled.Fingerprint),
        themeIcon = rememberVectorPainter(image = Icons.Filled.Brightness6),
        onChangePasswordClicked = presenter::onChangePasswordClicked,
        onTransferClick = presenter::onTransferClick,
        onManageDevicesClick = { navController.navigate(TrustedDevicesRoute) },
        onSyncActivityClick = { navController.navigate(SyncActivityRoute) },
        onReplacedBySyncClick = { navController.navigate(PreservedCopiesRoute) },
        onPrivacyPolicyClick = { uriHandler.openUri(PRIVACY_POLICY_URL) },
        onClipboardExpiryToggled = presenter::onClipboardExpiryToggled,
        onBiometricUnlockToggled = presenter::onBiometricUnlockToggled,
        onBiometricPasswordChanged = presenter::onBiometricPasswordChanged,
        onBiometricDialogDismissed = presenter::onBiometricDialogDismissed,
        onBiometricEnrollConfirmed = presenter::onBiometricEnrollConfirmed,
        themeMode = themeMode,
        onThemeModeSelected = { mode ->
            presenter.onThemeModeSelected(mode)
            onThemeModeChanged(mode)
        },
        portableVaultAccess = portableVaultAccess,
        portableVaultDialogVisible = portableVaultDialogVisible,
        onPortableVaultAccessClick = presenter::onPortableVaultAccessClicked,
        onPortableVaultDialogDismissed = presenter::onPortableVaultDialogDismissed,
        onPortableVaultRecoveryCopyClicked = presenter::onPortableVaultRecoveryCopyClicked,
        onPortableVaultRecoveryUpgradeClicked = presenter::onPortableVaultRecoveryUpgradeClicked,
    )
}

@Preview()
@Composable
fun PreviewSettings() {
    SettingsContent(
        oldPassword = "",
        newPassword = "",
        changePasswordDialogVisible = false,
        isChangingPassword = false,
        changePasswordError = null,
        clipboardExpiryEnabled = true,
        clipboardExpirySeconds = 30,
        biometricUnlock = BiometricUnlockState(BiometricAvailability.Available, enrolled = false),
        biometricPasswordDialogVisible = false,
        biometricPassword = "",
        isEnrollingBiometric = false,
        biometricUnlockError = null,
        appVersion = "v1.0.0 (6)",
        onOldPassUpdated = {},
        onNewPassUpdated = {},
        onChangePasswordDialogOpened = {},
        onChangePasswordDialogDismissed = {},
        changePassIcon = rememberVectorPainter(image = Icons.Filled.ChangeHistory),
        transferIcon = rememberVectorPainter(image = Icons.Filled.ImportExport),
        manageDevicesIcon = rememberVectorPainter(image = Icons.Filled.Devices),
        syncActivityIcon = rememberVectorPainter(image = Icons.Filled.History),
        replacedBySyncIcon = rememberVectorPainter(image = Icons.Filled.Restore),
        privacyIcon = rememberVectorPainter(image = Icons.Filled.Security),
        clipboardIcon = rememberVectorPainter(image = Icons.Filled.ContentPaste),
        biometricIcon = rememberVectorPainter(image = Icons.Filled.Fingerprint),
        themeIcon = rememberVectorPainter(image = Icons.Filled.Brightness6),
        onChangePasswordClicked = {},
        onTransferClick = {},
        onManageDevicesClick = {},
        onSyncActivityClick = {},
        onReplacedBySyncClick = {},
        onPrivacyPolicyClick = {},
        onClipboardExpiryToggled = {},
        onBiometricUnlockToggled = {},
        onBiometricPasswordChanged = {},
        onBiometricDialogDismissed = {},
        onBiometricEnrollConfirmed = {},
        themeMode = ThemeMode.System,
        onThemeModeSelected = {},
        portableVaultAccess = null,
        portableVaultDialogVisible = false,
        onPortableVaultAccessClick = {},
        onPortableVaultDialogDismissed = {},
        onPortableVaultRecoveryCopyClicked = {},
        onPortableVaultRecoveryUpgradeClicked = {},
    )
}

private const val PRIVACY_POLICY_URL = "https://sterlingalbury.com/passman/privacy-policy.html"
