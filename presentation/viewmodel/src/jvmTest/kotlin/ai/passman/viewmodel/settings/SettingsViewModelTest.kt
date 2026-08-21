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
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.initialization.GetAppVersion
import ai.passman.domain.initialization.models.AppInformation
import ai.passman.domain.initialization.models.Environment
import ai.passman.domain.initialization.models.Version
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.repository.BiometricUnlockRepository
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
    private val biometricUnlock = FakeBiometricUnlockRepository()

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
        biometrics: FakeBiometricUnlockRepository = biometricUnlock,
    ) = SettingsViewModel(
        changeUserPassword = ChangeUserPassword(userRepository, RecordingUserPreferences),
        getClipboardExpiry = GetClipboardExpiry(preferences),
        setClipboardExpiry = SetClipboardExpiry(preferences),
        getThemeMode = GetThemeMode(themePreferences),
        setThemeMode = SetThemeMode(themePreferences),
        getBiometricUnlockState = GetBiometricUnlockState(biometrics, RecordingUserPreferences),
        setBiometricUnlock = SetBiometricUnlock(biometrics, RecordingUserPreferences),
        getAppVersion = GetAppVersion(TEST_APP_INFORMATION),
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

    // ---------------------------------------------------------- biometric unlock

    /**
     * The switch does not follow the finger on the way ON.
     *
     * Enrolment makes a second copy of the master password, so it may only happen at a moment the
     * user has just proved they know it — and on a screen inside an already-unlocked session, the
     * only way to establish that is to ask. A switch that flipped on tap and back on failure would
     * be reporting an enrolment that does not exist.
     */
    @Test
    fun `turning it on asks for the master password instead of enrolling`() = runTest {
        val vm = newVm()
        runCurrent()

        vm.onBiometricUnlockToggled(true)
        runCurrent()

        assertTrue(vm.biometricPasswordDialogVisible.value)
        assertFalse(vm.biometricUnlock.value.enrolled, "nothing is enrolled until the password is confirmed")
        assertTrue(biometricUnlock.enableCalls.isEmpty())
    }

    @Test
    fun `a confirmed master password enrols and closes the dialog`() = runTest {
        val vm = newVm()
        runCurrent()

        vm.onBiometricUnlockToggled(true)
        vm.onBiometricPasswordChanged("master")
        vm.onBiometricEnrollConfirmed()
        runCurrent()

        assertEquals(listOf("mia" to "master"), biometricUnlock.enableCalls)
        assertTrue(vm.biometricUnlock.value.enrolled)
        assertFalse(vm.biometricPasswordDialogVisible.value)
        assertEquals("", vm.biometricPassword.value, "the master password must not outlive the enrolment")
        assertEquals("Biometric unlock turned on", vm.userMessages.receive())
    }

    @Test
    fun `a rejected master password keeps the dialog up with the reason`() = runTest {
        val vm = newVm()
        runCurrent()

        vm.onBiometricUnlockToggled(true)
        vm.onBiometricPasswordChanged("wrong")
        vm.onBiometricEnrollConfirmed()
        runCurrent()

        assertTrue(vm.biometricPasswordDialogVisible.value, "the user has to be able to read why and retry")
        assertEquals("Password is incorrect", vm.biometricUnlockError.value)
        assertFalse(vm.biometricUnlock.value.enrolled)
    }

    /** Destroying a secret needs no proof of anything; only creating one does. */
    @Test
    fun `turning it off disables without asking for a password`() = runTest {
        biometricUnlock.enrolled = true
        val vm = newVm()
        runCurrent()
        assertTrue(vm.biometricUnlock.value.enrolled)

        vm.onBiometricUnlockToggled(false)
        runCurrent()

        assertEquals(listOf("mia"), biometricUnlock.disableCalls)
        assertFalse(vm.biometricUnlock.value.enrolled)
        assertFalse(vm.biometricPasswordDialogVisible.value)
        assertEquals("Biometric unlock turned off", vm.userMessages.receive())
    }

    /**
     * The repository retires the enrolment as part of a successful change — the wrapped copy holds
     * the password that was just replaced. The switch has to say so, or it keeps claiming an
     * enrolment that no longer exists.
     */
    @Test
    fun `a successful master password change turns the switch off`() = runTest {
        biometricUnlock.enrolled = true
        val repository = GatedUserRepository()
        val vm = newVm(repository)
        runCurrent()
        assertTrue(vm.biometricUnlock.value.enrolled)

        vm.onChangePasswordClicked()
        runCurrent()
        repository.finish(Outcome.Success(AppUser.LoggedIn("mia", Password(hash = "h", salt = "s"))))
        runCurrent()

        assertFalse(vm.biometricUnlock.value.enrolled)
    }

    /** Hardware that will never have a sensor gets no row at all, rather than one that cannot move. */
    @Test
    fun `the row is withheld entirely on hardware with no sensor`() = runTest {
        biometricUnlock.availability = BiometricAvailability.NoHardware
        val vm = newVm()
        runCurrent()

        assertFalse(vm.biometricUnlock.value.offerable)
    }

    /** Every other unavailable state is something the user can fix, so the row stays and explains. */
    @Test
    fun `the row stays when the device simply has no biometric registered`() = runTest {
        biometricUnlock.availability = BiometricAvailability.NotEnrolled
        val vm = newVm()
        runCurrent()

        assertTrue(vm.biometricUnlock.value.offerable)
        assertFalse(vm.biometricUnlock.value.canUnlock)
    }

    /**
     * Same staleness rule the clipboard toggle has: a user who reaches the switch before the stored
     * value lands must not have their choice overwritten by the value that was stored before it.
     *
     * Only [BiometricUnlockState.enrolled] is stale-able, though. The device's availability is not
     * something the switch can change, and discarding it here would leave the row hidden for the
     * rest of the screen's life on the strength of one early tap.
     */
    @Test
    fun `a stored enrolment arriving after the user turns it off does not undo their choice`() = runTest {
        biometricUnlock.enrolled = true
        val vm = newVm()

        // Before runCurrent, so the startup read has not landed yet.
        vm.onBiometricUnlockToggled(false)
        runCurrent()

        assertFalse(vm.biometricUnlock.value.enrolled)
        assertEquals(listOf("mia"), biometricUnlock.disableCalls)
        assertTrue(vm.biometricUnlock.value.offerable, "the device fact from the late read still applies")
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

    override suspend fun signup(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun login(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioLogin(username: String): Outcome<AppUser> = unsupported()
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

    /** SetBiometricUnlock resolves the account it enrols from here rather than from its caller. */
    override suspend fun getUser(): AppUser = AppUser.LoggedIn("mia", Password(hash = "h", salt = "s"))
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("these tests only exercise the password change")
}

private object UnusedUserRepository : UserRepository {
    override suspend fun signup(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun login(username: String, password: String): Outcome<AppUser> = unsupported()
    override suspend fun bioLogin(username: String): Outcome<AppUser> = unsupported()
    override suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser> =
        unsupported()

    override suspend fun logout() = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("these tests only exercise the clipboard setting")
}

/**
 * Stands in for the whole platform stack behind biometric unlock. Only the two facts the settings
 * screen can observe are modelled — what the device can do, and whether this account is enrolled —
 * plus the one rule the screen must respect: nothing is enrolled unless the master password is
 * right, so [enable] can refuse.
 */
private class FakeBiometricUnlockRepository(
    var availability: BiometricAvailability = BiometricAvailability.Available,
) : BiometricUnlockRepository {
    var enrolled = false
    var acceptedPassword = "master"
    val enableCalls = mutableListOf<Pair<String, String>>()
    val disableCalls = mutableListOf<String>()

    override suspend fun biometricUnlockState(username: String) =
        BiometricUnlockState(availability = availability, enrolled = enrolled)

    override suspend fun biometricAvailability() = availability

    override suspend fun enable(username: String, password: String): Outcome<Unit> {
        enableCalls += username to password
        if (availability != BiometricAvailability.Available) {
            return Outcome.Error("Biometric unlock is unavailable on this device", AuthFailure.BioAuthUnavailable)
        }
        if (password != acceptedPassword) return Outcome.Error("Password is incorrect", AuthFailure.InvalidPassword)
        enrolled = true
        return Outcome.Success(Unit)
    }

    override suspend fun disable(username: String) {
        disableCalls += username
        enrolled = false
    }

    override suspend fun enrolmentOffered(username: String) = username in offered

    override suspend fun recordEnrolmentOffered(username: String) {
        offered += username
    }

    /** The settings toggle never consults this; it is here so the fake satisfies the contract. */
    private val offered = mutableSetOf<String>()
}

/** Only the version name and build number are read from it; the rest is filler the type requires. */
private val TEST_APP_INFORMATION = AppInformation(
    version = Version(name = "1.0.0", build = "0", additionalInfo = ""),
    versionCode = 6,
    id = "ai.passman",
    environment = Environment.PROD,
    debug = false,
    userHomeDir = "/tmp",
)
