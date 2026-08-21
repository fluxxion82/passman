package ai.passman.viewmodel.settings

import ai.passman.domain.base.invoke
import ai.passman.domain.initialization.GetAppVersion
import ai.passman.domain.settings.GetClipboardExpiry
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.domain.settings.GetThemeMode
import ai.passman.domain.settings.SetClipboardExpiry
import ai.passman.domain.settings.SetThemeMode
import ai.passman.domain.settings.GetPortableVaultAccess
import ai.passman.domain.settings.UpgradePortableVaultRecovery
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.user.ChangeUserPassword
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.base.model.Outcome
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.SettingsNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class SettingsViewModel(
    val changeUserPassword: ChangeUserPassword,
    private val getClipboardExpiry: GetClipboardExpiry,
    private val setClipboardExpiry: SetClipboardExpiry,
    private val getThemeMode: GetThemeMode,
    private val setThemeMode: SetThemeMode,
    private val getBiometricUnlockState: GetBiometricUnlockState,
    private val setBiometricUnlock: SetBiometricUnlock,
    private val getAppVersion: GetAppVersion,
    private val getPortableVaultAccess: GetPortableVaultAccess? = null,
    private val copyToClipboard: CopyToClipboard? = null,
    private val upgradePortableVaultRecovery: UpgradePortableVaultRecovery? = null,
) : BaseViewModel() {
    val navigation = Channel<SettingsNavigation>(Channel.RENDEZVOUS)
    val userMessages = Channel<String>(Channel.BUFFERED)
    val oldPassword = MutableStateFlow("")
    val newPassword = MutableStateFlow("")

    /**
     * Whether the change-password dialog is up, held here rather than in the composable because the
     * only thing allowed to close it is a *successful* change — see [onChangePasswordClicked].
     */
    val changePasswordDialogVisible = MutableStateFlow(false)

    /**
     * True from the moment the change is handed to the use case until its outcome is known.
     *
     * The UI blocks on this: no dismiss, no back-press, no second submit. A master-password change
     * is two Argon2id derivations plus a staged keyring verify — seconds of work — and this
     * ViewModel dies with the back stack. A user who logged out mid-change had the job cancelled
     * under it and was told nothing, while the repository correctly threw the staged keyring away;
     * the password had not changed but the user believed it had.
     */
    val isChangingPassword = MutableStateFlow(false)

    /**
     * Why the last change failed, shown inside the dialog.
     *
     * The message also goes to [userMessages] as it always has, but a snackbar is drawn in the
     * screen's window and the dialog is a window in front of it — now that a failure keeps the
     * dialog up, the dialog is the only place the user can actually read the reason.
     */
    val changePasswordError = MutableStateFlow<String?>(null)

    /**
     * Shown as on until the stored value arrives, which is also what it is by default — the toggle
     * never renders as "off" for an install that has the expiry switched on.
     */
    val clipboardExpiryEnabled = MutableStateFlow(ClipboardExpiry.Default.enabled)

    /**
     * Published so the settings copy can state the real timeout rather than a number baked into a
     * string that goes stale the moment the duration is tuned.
     */
    val clipboardExpirySeconds = MutableStateFlow(ClipboardExpiry.Default.duration.inWholeSeconds)
    val themeMode = MutableStateFlow(ThemeMode.System)

    /**
     * Empty until the read lands, and empty is what the row renders as nothing at all — a build
     * line that flashes a placeholder is worse than one that appears a frame late.
     */
    val appVersion = MutableStateFlow("")
    val portableVaultAccess = MutableStateFlow<PortableVaultAccess?>(null)
    val portableVaultDialogVisible = MutableStateFlow(false)

    /**
     * Enrolment state for the signed-in account.
     *
     * Starts as [BiometricUnlockState.Unsupported] rather than "available but off": the startup
     * read is suspending, and a row that appears a frame later is better than one that appears
     * switched off on a device that turns out to have no sensor at all.
     */
    val biometricUnlock = MutableStateFlow(BiometricUnlockState.Unsupported)

    /**
     * Turning it ON opens this; turning it off does not.
     *
     * Enrolment stores a copy of the master password, so it may only happen at a moment the user
     * has just proved they know it — which on a screen reachable from an already-unlocked session
     * means asking again. Turning it off destroys a secret and needs no such proof.
     */
    val biometricPasswordDialogVisible = MutableStateFlow(false)
    val biometricPassword = MutableStateFlow("")

    /** Set while the system prompt is up. The dialog blocks on it for the same reason the
     * change-password dialog blocks on [isChangingPassword]: leaving kills the ViewModel. */
    val isEnrollingBiometric = MutableStateFlow(false)

    /** Why the last enrolment failed, shown in the dialog rather than only as a snackbar. */
    val biometricUnlockError = MutableStateFlow<String?>(null)

    /** Kept whole so toggling the flag preserves whatever duration is configured. */
    private var clipboardExpiry = ClipboardExpiry.Default

    /**
     * Set the moment the user touches the toggle, and never unset. The startup read is a suspending
     * call, so a user who reaches the switch before it lands would otherwise have their choice
     * overwritten by the value that was stored *before* they made it — the switch would flip back
     * under their finger, and the write they triggered would look like it failed.
     */
    private var expiryChangedByUser = false
    private var themeChangedByUser = false
    private var biometricChangedByUser = false

    init {
        viewModelScope.launch {
            val stored = getClipboardExpiry()
            // Stale by the time it arrived: the user has since said what they want, and their
            // choice is already on its way to the store.
            if (expiryChangedByUser) return@launch
            clipboardExpiry = stored
            clipboardExpiryEnabled.value = stored.enabled
            clipboardExpirySeconds.value = stored.duration.inWholeSeconds
        }
        viewModelScope.launch {
            val stored = getThemeMode()
            if (themeChangedByUser) return@launch
            themeMode.value = stored
        }
        viewModelScope.launch {
            appVersion.value = getAppVersion()
        }
        refreshBiometricUnlock()
    }

    private fun refreshBiometricUnlock() {
        viewModelScope.launch {
            val state = getBiometricUnlockState(GetBiometricUnlockState.Request.ForSignedInUser)
            // Same staleness rule as the clipboard toggle, but applied to half the value: only
            // `enrolled` can be stale, because only `enrolled` is something the user may have
            // changed while the read was in flight. Availability is a device fact they cannot
            // touch from here — dropping it would leave the row hidden for the rest of the screen's
            // life on the strength of one early tap.
            biometricUnlock.value = if (biometricChangedByUser) {
                biometricUnlock.value.copy(availability = state.availability)
            } else {
                state
            }
        }
    }

    fun onOldPasswordChanged(oldPass: String) {
        // The message described the values as they were; the user is changing them.
        changePasswordError.value = null
        oldPassword.value = oldPass
    }

    fun onNewPasswordChanged(newPass: String) {
        changePasswordError.value = null
        newPassword.value = newPass
    }

    fun onClipboardExpiryToggled(enabled: Boolean) {
        expiryChangedByUser = true
        clipboardExpiryEnabled.value = enabled
        viewModelScope.launch {
            clipboardExpiry = clipboardExpiry.copy(enabled = enabled)
            setClipboardExpiry(clipboardExpiry)
        }
    }

    /**
     * The switch does not move here on the way ON, and that is deliberate: it reports enrolment,
     * and nothing is enrolled until the password has been verified and a prompt has been answered.
     * A switch that flipped on tap and back on failure would read as a bug.
     */
    fun onBiometricUnlockToggled(enabled: Boolean) {
        biometricChangedByUser = true
        biometricUnlockError.value = null
        if (enabled) {
            biometricPassword.value = ""
            biometricPasswordDialogVisible.value = true
            return
        }
        viewModelScope.launch {
            setBiometricUnlock(SetBiometricUnlock.Request.Disable)
            biometricUnlock.value = biometricUnlock.value.copy(enrolled = false)
            userMessages.send("Biometric unlock turned off")
        }
    }

    fun onBiometricPasswordChanged(password: String) {
        biometricUnlockError.value = null
        biometricPassword.value = password
    }

    /** Ignored while the system prompt is up — see [isEnrollingBiometric]. */
    fun onBiometricDialogDismissed() {
        if (isEnrollingBiometric.value) return
        biometricPasswordDialogVisible.value = false
        biometricPassword.value = ""
    }

    fun onBiometricEnrollConfirmed() {
        if (isEnrollingBiometric.value) return
        biometricUnlockError.value = null
        isEnrollingBiometric.value = true
        viewModelScope.launch {
            try {
                when (val outcome = setBiometricUnlock(SetBiometricUnlock.Request.Enable(biometricPassword.value))) {
                    is Outcome.Success -> {
                        biometricPasswordDialogVisible.value = false
                        // Cleared on the way out, not on the way in: the string is the master
                        // password and there is no reason for it to outlive the enrolment.
                        biometricPassword.value = ""
                        // Stated outright rather than copied onto whatever is there: enrolment only
                        // succeeds when the device can authenticate, so a success settles both
                        // halves — including on the startup read that has not landed yet.
                        biometricUnlock.value = BiometricUnlockState(BiometricAvailability.Available, enrolled = true)
                        userMessages.send("Biometric unlock turned on")
                    }
                    is Outcome.Error -> {
                        biometricUnlockError.value = outcome.message
                        userMessages.send(outcome.message)
                    }
                }
            } finally {
                isEnrollingBiometric.value = false
            }
        }
    }

    fun onThemeModeSelected(mode: ThemeMode) {
        themeChangedByUser = true
        themeMode.value = mode
        viewModelScope.launch {
            setThemeMode(mode)
        }
    }

    fun onChangePasswordDialogOpened() {
        changePasswordError.value = null
        changePasswordDialogVisible.value = true
    }

    /**
     * Ignored while a change is in flight. The dialog is the only thing keeping the user on this
     * screen, and leaving it is what kills the ViewModel — and with it the change.
     */
    fun onChangePasswordDialogDismissed() {
        if (isChangingPassword.value) return
        changePasswordDialogVisible.value = false
    }

    fun onChangePasswordClicked() {
        // A second submit would run a second change against credentials the first one is in the
        // middle of replacing.
        if (isChangingPassword.value) return
        changePasswordError.value = null
        isChangingPassword.value = true
        viewModelScope.launch {
            try {
                when (val outcome = changeUserPassword(ChangeUserPassword.ChangePasswordRequest(oldPassword.value, newPassword.value))) {
                    is Outcome.Success -> {
                        // Only a success closes the dialog: an error has to stay in front of the
                        // user with the fields they typed and the reason it failed.
                        changePasswordDialogVisible.value = false
                        oldPassword.value = ""
                        newPassword.value = ""
                        // The repository retires the biometric enrolment as part of a successful
                        // change — the wrapped copy holds the password that was just replaced. Say
                        // so here, or the switch keeps claiming an enrolment that no longer exists.
                        biometricUnlock.value = biometricUnlock.value.copy(enrolled = false)
                        userMessages.send("Master password changed")
                    }
                    is Outcome.Error -> {
                        changePasswordError.value = outcome.message
                        userMessages.send(outcome.message)
                    }
                }
            } finally {
                isChangingPassword.value = false
            }
        }
    }

    fun onTransferClick() {
        viewModelScope.launch {
            navigation.send(SettingsNavigation.Transfer(false))
        }
    }

    fun onPortableVaultAccessClicked() {
        val access = getPortableVaultAccess ?: run {
            viewModelScope.launch { userMessages.send("Portable vault recovery is unavailable") }
            return
        }
        viewModelScope.launch {
            when (val outcome = access()) {
                is Outcome.Success -> {
                    portableVaultAccess.value = outcome.value
                    portableVaultDialogVisible.value = true
                }
                is Outcome.Error -> userMessages.send(outcome.message)
            }
        }
    }

    fun onPortableVaultDialogDismissed() {
        portableVaultDialogVisible.value = false
        portableVaultAccess.value = null
    }

    fun onPortableVaultRecoveryCopyClicked() {
        val recoveryPassword = portableVaultAccess.value?.recoveryPassword ?: return
        val copy = copyToClipboard ?: run {
            viewModelScope.launch { userMessages.send("Clipboard access is unavailable") }
            return
        }
        viewModelScope.launch {
            copy(recoveryPassword)
            userMessages.send("Recovery secret copied")
        }
    }

    /** This is only available for legacy records and is never run while Settings is opened. */
    fun onPortableVaultRecoveryUpgradeClicked() {
        val current = portableVaultAccess.value ?: return
        if (current.recoveryFormat != ai.passman.domain.settings.model.PortableVaultRecoveryFormat.LegacyBase64Url) return
        val upgrade = upgradePortableVaultRecovery ?: run {
            viewModelScope.launch { userMessages.send("Recovery phrase upgrade is unavailable") }
            return
        }
        viewModelScope.launch {
            when (val outcome = upgrade()) {
                is Outcome.Success -> portableVaultAccess.value = outcome.value
                is Outcome.Error -> userMessages.send(outcome.message)
            }
        }
    }
}
