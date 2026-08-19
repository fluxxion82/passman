package ai.passman.viewmodel.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.exception.Failure
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.GetClipboardExpiry
import ai.passman.domain.settings.GetPortableVaultAccess
import ai.passman.domain.settings.GetThemeMode
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.domain.settings.SetClipboardExpiry
import ai.passman.domain.settings.SetThemeMode
import ai.passman.domain.settings.UpgradePortableVaultRecovery
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.model.PortableVaultRecoveryFormat
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.settings.repository.ClipboardPreferences
import ai.passman.domain.settings.repository.ThemePreferences
import ai.passman.domain.user.ChangeUserPassword
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk

/**
 * The clipboard-expiry toggle is a security setting the user can reach the instant the screen
 * appears, while the stored value it renders is still being read. What must never happen is the
 * switch answering to anything other than the last thing the user said.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SettingsViewModelTest {

    private val preferences = FakeClipboardPreferences(ClipboardExpiry(enabled = true, duration = 30.seconds))
    private val themePreferences = FakeThemePreferences(ThemeMode.System)

    @BeforeTest
    fun setup() {
        // Standard, not unconfined: the point of these tests is what happens while the startup
        // read is still outstanding, so nothing may run until the test says so.
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm(
        userRepository: UserRepository = UnusedUserRepository,
        getPortableVaultAccess: GetPortableVaultAccess? = null,
        copyToClipboard: CopyToClipboard? = null,
        upgradePortableVaultRecovery: UpgradePortableVaultRecovery? = null,
    ) = SettingsViewModel(
        changeUserPassword = ChangeUserPassword(userRepository, RecordingUserPreferences),
        getClipboardExpiry = GetClipboardExpiry(preferences),
        setClipboardExpiry = SetClipboardExpiry(preferences),
        getThemeMode = GetThemeMode(themePreferences),
        setThemeMode = SetThemeMode(themePreferences),
        getPortableVaultAccess = getPortableVaultAccess,
        copyToClipboard = copyToClipboard,
        upgradePortableVaultRecovery = upgradePortableVaultRecovery,
    )

    @Test
    fun `the stored setting is what the toggle ends up showing`() = runTest {
        preferences.stored = ClipboardExpiry(enabled = false, duration = 90.seconds)
        val vm = newVm()

        runCurrent()

        assertFalse(vm.clipboardExpiryEnabled.value)
        assertEquals(90, vm.clipboardExpirySeconds.value)
    }

    /** Until it arrives the switch shows the default, which is what a fresh install has anyway. */
    @Test
    fun `the toggle shows the expiry as on until the stored value arrives`() {
        val vm = newVm()

        assertTrue(vm.clipboardExpiryEnabled.value)
        assertEquals(30, vm.clipboardExpirySeconds.value)
    }

    /**
     * The race the guard exists for. The user reaches the switch before the startup read lands, and
     * the value that was stored *before* they touched it arrives afterwards. Without the guard it
     * overwrites their choice: the switch flips back under their finger, the write they triggered
     * has already gone to the store, and the screen now disagrees with the setting.
     */
    @Test
    fun `a stored value arriving after the user has toggled does not undo their choice`() = runTest {
        preferences.gateFirstRead()
        val vm = newVm()
        runCurrent()

        vm.onClipboardExpiryToggled(false)
        runCurrent()

        // Only now does the startup read — begun before the tap — complete, carrying the old value.
        preferences.releaseFirstRead()
        runCurrent()

        assertFalse(
            vm.clipboardExpiryEnabled.value,
            "the startup read flipped the switch back on over the user's choice",
        )
        assertEquals(
            ClipboardExpiry(enabled = false, duration = 30.seconds),
            preferences.stored,
            "the user's choice must still be what was persisted",
        )
    }

    @Test
    fun `toggling persists the flag and keeps the configured duration`() = runTest {
        preferences.stored = ClipboardExpiry(enabled = true, duration = 90.seconds)
        val vm = newVm()
        runCurrent()

        vm.onClipboardExpiryToggled(false)
        runCurrent()

        assertEquals(ClipboardExpiry(enabled = false, duration = 90.seconds), preferences.stored)
        assertFalse(vm.clipboardExpiryEnabled.value)
        assertEquals(90, vm.clipboardExpirySeconds.value)
    }

    /**
     * A master-password change is seconds of Argon2id, and this ViewModel dies with the back stack.
     * A user who dismissed the dialog and logged out mid-change had the job cancelled under them and
     * was told nothing, so the dialog has to hold them there until the outcome is known: no dismiss,
     * no second submit, and a progress indicator while it runs.
     */
    @Test
    fun `the dialog reports the change as in flight until the outcome arrives`() = runTest {
        val repository = GatedUserRepository()
        val vm = newVm(repository)
        vm.onChangePasswordDialogOpened()
        runCurrent()

        vm.onChangePasswordClicked()
        runCurrent()

        assertTrue(vm.isChangingPassword.value, "the change is running; the dialog must say so")
        vm.onChangePasswordDialogDismissed()
        assertTrue(vm.changePasswordDialogVisible.value, "a dismiss mid-change must be ignored")

        repository.finish(Outcome.Success(AppUser.LoggedIn("alice", Password("h", "s", null))))
        runCurrent()

        assertFalse(vm.isChangingPassword.value)
        assertFalse(vm.changePasswordDialogVisible.value, "a successful change closes the dialog")
        assertEquals("Master password changed", vm.userMessages.receive())
    }

    /** A second tap while the first change is still running would race its own credential write. */
    @Test
    fun `a second submit while a change is running is ignored`() = runTest {
        val repository = GatedUserRepository()
        val vm = newVm(repository)
        vm.onChangePasswordClicked()
        runCurrent()

        vm.onChangePasswordClicked()
        runCurrent()

        assertEquals(1, repository.calls, "the change must not be launched twice")
        repository.finish(Outcome.Success(AppUser.LoggedIn("alice", Password("h", "s", null))))
        runCurrent()
    }

    /** A failure keeps the user in front of the dialog, with the message the change produced. */
    @Test
    fun `a failed change leaves the dialog open with its message`() = runTest {
        val repository = GatedUserRepository()
        val vm = newVm(repository)
        vm.onChangePasswordDialogOpened()
        vm.onChangePasswordClicked()
        runCurrent()

        repository.finish(Outcome.Error("Password is incorrect", TestFailure))
        runCurrent()

        assertFalse(vm.isChangingPassword.value)
        assertTrue(vm.changePasswordDialogVisible.value, "a failed change must not close the dialog")
        assertEquals("Password is incorrect", vm.userMessages.receive())
        assertEquals(
            "Password is incorrect",
            vm.changePasswordError.value,
            "the dialog is in front of the snackbar, so the reason has to be readable inside it",
        )

        // Editing a field makes the message stale — it described what was typed before.
        vm.onOldPasswordChanged("another guess")
        assertNull(vm.changePasswordError.value)

        // And with nothing in flight, the user can now leave.
        vm.onChangePasswordDialogDismissed()
        assertFalse(vm.changePasswordDialogVisible.value)
    }

    @Test
    fun `each theme selection updates state and persists`() = runTest {
        val vm = newVm()
        runCurrent()

        listOf(ThemeMode.System, ThemeMode.Light, ThemeMode.Dark).forEach { mode ->
            vm.onThemeModeSelected(mode)
            runCurrent()

            assertEquals(mode, vm.themeMode.value)
            assertEquals(mode, themePreferences.stored)
        }
    }

    @Test
    fun `a stored theme arriving after the user selects a mode does not undo their choice`() = runTest {
        themePreferences.stored = ThemeMode.Light
        themePreferences.gateFirstRead()
        val vm = newVm()
        runCurrent()

        vm.onThemeModeSelected(ThemeMode.Dark)
        runCurrent()

        themePreferences.releaseFirstRead()
        runCurrent()

        assertEquals(
            ThemeMode.Dark,
            vm.themeMode.value,
            "the startup read overwrote the user's selected theme",
        )
        assertEquals(ThemeMode.Dark, themePreferences.stored)
    }

    @Test
    fun `copying displayed recovery material sends its exact secret to the clipboard use case`() = runTest {
        val getAccess = mockk<GetPortableVaultAccess>()
        val copy = mockk<CopyToClipboard>(relaxed = true)
        val access = legacyAccess()
        coEvery { getAccess.invoke() } returns Outcome.Success(access)
        val vm = newVm(getPortableVaultAccess = getAccess, copyToClipboard = copy)

        vm.onPortableVaultAccessClicked()
        runCurrent()
        vm.onPortableVaultRecoveryCopyClicked()
        runCurrent()

        coVerify(exactly = 1) { copy.invoke(access.recoveryPassword) }
        assertEquals("Recovery secret copied", vm.userMessages.receive())
    }

    @Test
    fun `an explicit legacy upgrade replaces the displayed recovery secret with a phrase`() = runTest {
        val getAccess = mockk<GetPortableVaultAccess>()
        val upgrade = mockk<UpgradePortableVaultRecovery>()
        val legacy = legacyAccess()
        val phrase = phraseAccess()
        coEvery { getAccess.invoke() } returns Outcome.Success(legacy)
        coEvery { upgrade.invoke() } returns Outcome.Success(phrase)
        val vm = newVm(getPortableVaultAccess = getAccess, upgradePortableVaultRecovery = upgrade)

        vm.onPortableVaultAccessClicked()
        runCurrent()
        vm.onPortableVaultRecoveryUpgradeClicked()
        runCurrent()

        assertEquals(phrase, vm.portableVaultAccess.value)
        assertTrue(vm.portableVaultDialogVisible.value)
        coVerify(exactly = 1) { upgrade.invoke() }
    }

    @Test
    fun `a failed legacy upgrade leaves the displayed recovery secret intact`() = runTest {
        val getAccess = mockk<GetPortableVaultAccess>()
        val upgrade = mockk<UpgradePortableVaultRecovery>()
        val legacy = legacyAccess()
        coEvery { getAccess.invoke() } returns Outcome.Success(legacy)
        coEvery { upgrade.invoke() } returns Outcome.Error("Recovery upgrade failed", TestFailure)
        val vm = newVm(getPortableVaultAccess = getAccess, upgradePortableVaultRecovery = upgrade)

        vm.onPortableVaultAccessClicked()
        runCurrent()
        vm.onPortableVaultRecoveryUpgradeClicked()
        runCurrent()

        assertEquals(legacy, vm.portableVaultAccess.value)
        assertEquals("Recovery upgrade failed", vm.userMessages.receive())
    }
}

private fun legacyAccess() = PortableVaultAccess(
    profileDirectory = "/tmp/profile",
    pkcs12Path = "/tmp/profile/legacy.recovery.p12",
    certificatePath = "/tmp/profile/legacy.recovery.crt",
    vaultPath = "/tmp/vault.cms",
    recoveryPassword = "K5M75bFE9Vqapxvt_KiOv0_9k7tKEtQJ1-aNSkN0KpQ",
    recoveryFormat = PortableVaultRecoveryFormat.LegacyBase64Url,
)

private fun phraseAccess() = legacyAccess().copy(
    recoveryPassword = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    recoveryFormat = PortableVaultRecoveryFormat.Bip39English24,
)

private class FakeClipboardPreferences(var stored: ClipboardExpiry) : ClipboardPreferences {
    private var gate: CompletableDeferred<Unit>? = null
    private var reads = 0

    /** Parks the next read until [releaseFirstRead], modelling a slow store on a cold start. */
    fun gateFirstRead() {
        gate = CompletableDeferred()
    }

    fun releaseFirstRead() {
        gate?.complete(Unit)
    }

    override suspend fun getExpiry(): ClipboardExpiry {
        // The answer is fixed before the read parks, which is the whole point: a read already on
        // its way back carries the value as it was *then*. Re-reading the store on the way out
        // would quietly hand back the user's own change and prove nothing.
        val answer = stored
        if (reads++ == 0) gate?.await()
        return answer
    }

    override suspend fun setExpiry(expiry: ClipboardExpiry) {
        stored = expiry
    }
}

private class FakeThemePreferences(var stored: ThemeMode) : ThemePreferences {
    private var gate: CompletableDeferred<Unit>? = null
    private var reads = 0

    fun gateFirstRead() {
        gate = CompletableDeferred()
    }

    fun releaseFirstRead() {
        gate?.complete(Unit)
    }

    override suspend fun getMode(): ThemeMode {
        val answer = stored
        if (reads++ == 0) gate?.await()
        return answer
    }

    override suspend fun setMode(mode: ThemeMode) {
        stored = mode
    }
}

/**
 * A change that does not answer until the test says so — the several seconds of Argon2id the real
 * one costs, compressed to the one property the dialog cares about.
 */
private class GatedUserRepository : UserRepository {
    var calls = 0
        private set

    private var outcome = CompletableDeferred<Outcome<AppUser>>()

    fun finish(result: Outcome<AppUser>) {
        outcome.complete(result)
    }

    override suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser> {
        calls++
        return outcome.await()
    }

    override suspend fun signup(username: String, password: String, pgpPassphrase: String): Outcome<AppUser> = unsupported()
    override suspend fun login(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioLogin(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioSignup(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun logout() = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("these tests only exercise the password change")
}

private object TestFailure : Failure.FeatureFailure()

/** The use case upserts whatever a successful change returns; nothing here reads it back. */
private object RecordingUserPreferences : UserPreferences {
    var upserted: AppUser? = null
        private set

    override suspend fun upsert(user: AppUser) {
        upserted = user
    }

    override suspend fun getUser(): AppUser = unsupported()
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("these tests only exercise the password change")
}

private object UnusedUserRepository : UserRepository {
    override suspend fun signup(username: String, password: String, pgpPassphrase: String): Outcome<AppUser> = unsupported()
    override suspend fun login(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioLogin(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioSignup(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser> =
        unsupported()

    override suspend fun logout() = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("these tests only exercise the clipboard setting")
}
