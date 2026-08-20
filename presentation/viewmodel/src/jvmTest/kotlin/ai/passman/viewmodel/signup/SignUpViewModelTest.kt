package ai.passman.viewmodel.signup

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetBiometricAvailability
import ai.passman.domain.user.RecordBiometricUnlockOffered
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.SignUpUser
import ai.passman.domain.user.ValidateSignUpCredentials
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.models.PasswordStrength
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.viewvo.signup.SignUpNavigation
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

@OptIn(ExperimentalCoroutinesApi::class)
class SignUpViewModelTest {
    private val signUpUser: SignUpUser = mockk(relaxed = true)

    private val strongPassword = "correct-Horse-battery-9"

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm(
        // NoHardware by default — the desktop answer — so the signup-mechanics tests below see a
        // form with no checkbox on it, which is what those devices actually get.
        biometrics: FakeBiometricUnlockRepository =
            FakeBiometricUnlockRepository(availability = BiometricAvailability.NoHardware),
    ) = SignUpViewModel(
        signUpUser = signUpUser,
        validateSignUpCredentials = ValidateSignUpCredentials(),
        getBiometricAvailability = GetBiometricAvailability(biometrics),
        setBiometricUnlock = SetBiometricUnlock(biometrics, SignedInUserPreferences),
        recordBiometricUnlockOffered = RecordBiometricUnlockOffered(biometrics, SignedInUserPreferences),
    )

    private fun SignUpViewModel.fillValid() {
        onUsernameChange("mia")
        onPasswordChange(strongPassword)
        onConfirmPasswordChange(strongPassword)
    }

    @Test
    fun `empty fields report missing information`() = runTest {
        val vm = newVm()
        vm.onSignupClicked()
        runCurrent()
        assertEquals(SignUpNavigation.MissingInformation, vm.navigation.receive())
    }

    @Test
    fun `short password is rejected before the account is created`() = runTest {
        val vm = newVm()
        vm.onUsernameChange("mia")
        vm.onPasswordChange("elevenchars")
        vm.onConfirmPasswordChange("elevenchars")

        vm.onSignupClicked()
        runCurrent()

        assertEquals(
            SignUpNavigation.InvalidCredentials("Master password must be at least 12 characters"),
            vm.navigation.receive(),
        )
        coVerify(exactly = 0) { signUpUser.invoke(any()) }
    }

    @Test
    fun `password containing the username is rejected`() = runTest {
        val vm = newVm()
        vm.onUsernameChange("sterling")
        vm.onPasswordChange("mySterlingPass99")
        vm.onConfirmPasswordChange("mySterlingPass99")

        vm.onSignupClicked()
        runCurrent()

        assertEquals(
            SignUpNavigation.InvalidCredentials("Password must not contain your username"),
            vm.navigation.receive(),
        )
        coVerify(exactly = 0) { signUpUser.invoke(any()) }
    }

    @Test
    fun `padding spaces do not count toward the minimum length`() = runTest {
        val vm = newVm()
        vm.onUsernameChange("mia")
        // 13 characters raw, 11 after the trim SignUpUser applies before storing.
        vm.onPasswordChange(" elevenchars ")
        vm.onConfirmPasswordChange(" elevenchars ")

        vm.onSignupClicked()
        runCurrent()

        assertEquals(
            SignUpNavigation.InvalidCredentials("Master password must be at least 12 characters"),
            vm.navigation.receive(),
        )
    }

    @Test
    fun `mismatched confirmation is rejected`() = runTest {
        val vm = newVm()
        vm.onUsernameChange("mia")
        vm.onPasswordChange(strongPassword)
        vm.onConfirmPasswordChange(strongPassword + "x")

        vm.onSignupClicked()
        runCurrent()

        assertEquals(
            SignUpNavigation.InvalidCredentials("Passwords do not match"),
            vm.navigation.receive(),
        )
        coVerify(exactly = 0) { signUpUser.invoke(any()) }
    }

    @Test
    fun `valid credentials sign up and navigate to success`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)

        val vm = newVm()
        vm.fillValid()
        vm.onSignupClicked()
        runCurrent()

        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
        coVerify(exactly = 1) {
            signUpUser.invoke(SignUpUser.SignUpRequest.Standard("mia", strongPassword))
        }
    }

    @Test
    fun `second click while signup is in flight is ignored`() = runTest {
        coEvery { signUpUser.invoke(any()) } coAnswers {
            delay(5_000)
            Outcome.Success(UserState.LoggedIn)
        }

        val vm = newVm()
        vm.fillValid()
        vm.onSignupClicked()
        runCurrent()
        vm.onSignupClicked()
        runCurrent()

        advanceUntilIdle()
        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
        coVerify(exactly = 1) { signUpUser.invoke(any()) }
    }

    @Test
    fun `password strength is exposed for the meter`() = runTest {
        val vm = newVm()
        vm.onPasswordChange("Qwertzuiopasdfghjkl9")
        runCurrent()
        assertEquals(PasswordStrength.Strong, vm.passwordStrength.value)
    }

    // ------------------------------------------- the biometric checkbox

    /**
     * The checkbox exists at all only on a device that can enrol. A sensorless phone — and every
     * desktop, which reports [BiometricAvailability.NoHardware] — gets a form without it rather
     * than one carrying a tick box that could never do anything.
     */
    @Test
    fun `the checkbox is absent when the device cannot authenticate`() = runTest {
        BiometricAvailability.entries.filter { it != BiometricAvailability.Available }.forEach { availability ->
            val vm = newVm(FakeBiometricUnlockRepository(availability = availability))

            runCurrent()

            assertFalse(vm.biometricOfferable.value, "$availability must not draw the checkbox")
        }
    }

    @Test
    fun `the checkbox is offered on a device that can authenticate`() = runTest {
        val vm = newVm(FakeBiometricUnlockRepository())

        runCurrent()

        assertTrue(vm.biometricOfferable.value)
        assertFalse(vm.enrolBiometric.value, "it starts unticked; enrolling is opt-in")
    }

    /**
     * The point of a checkbox over a dialog: the decision was made on the form, so nothing is
     * asked a second time. The password is the one already in the view model — trimmed the way
     * [SignUpUser] trims it before storing the credential it will be verified against.
     */
    @Test
    fun `a ticked box enrols after signup with the password already held`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository()
        val vm = newVm(biometrics)
        runCurrent()

        vm.onUsernameChange("mia")
        vm.onPasswordChange("  $strongPassword  ")
        vm.onConfirmPasswordChange("  $strongPassword  ")
        vm.onEnrolBiometricChanged(true)
        vm.onSignupClicked()
        runCurrent()

        assertEquals(listOf("mia" to strongPassword), biometrics.enableCalls)
        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
    }

    /** The checkbox value is intent only — it must never reach the account bootstrap. */
    @Test
    fun `ticking the box does not change what signup is asked to create`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val vm = newVm(FakeBiometricUnlockRepository())
        runCurrent()

        vm.fillValid()
        vm.onEnrolBiometricChanged(true)
        vm.onSignupClicked()
        runCurrent()
        vm.navigation.receive()

        coVerify(exactly = 1) {
            signUpUser.invoke(SignUpUser.SignUpRequest.Standard("mia", strongPassword))
        }
    }

    @Test
    fun `an unticked box enrols nothing`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository()
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onSignupClicked()
        runCurrent()

        assertTrue(biometrics.enableCalls.isEmpty())
        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
    }

    /**
     * An unticked box is a "no", given on the form. The login dialog exists to collect that same
     * "no" from accounts that never saw a checkbox, so signup spends the offer on its own behalf —
     * otherwise the very next login asks, as a modal, what this form already asked.
     */
    @Test
    fun `an unticked box spends the account's one enrolment offer`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository()
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onSignupClicked()
        runCurrent()
        vm.navigation.receive()

        assertEquals(setOf("mia"), biometrics.offered)
    }

    /**
     * The other half of that decision: a user who ticked the box *wanted* this, so a prompt they
     * could not complete leaves the offer unspent and the login dialog becomes their retry rather
     * than a repetition.
     */
    @Test
    fun `a refused prompt leaves the offer unspent so the login dialog can retry`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository().apply {
            enableFailure = Outcome.Error("Biometric unlock was cancelled", AuthFailure.BioAuthCancelled)
        }
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onEnrolBiometricChanged(true)
        vm.onSignupClicked()
        runCurrent()
        vm.navigation.receive()

        assertTrue(biometrics.offered.isEmpty())
    }

    /** A cancelled prompt is a setting they did not get, not a signup they did not make. */
    @Test
    fun `a refused prompt still lands the user in the app`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository().apply {
            enableFailure = Outcome.Error("Biometric unlock was cancelled", AuthFailure.BioAuthCancelled)
        }
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onEnrolBiometricChanged(true)
        vm.onSignupClicked()
        runCurrent()

        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
        runCurrent()
        assertFalse(vm.isLoading.value)
    }

    /** Same rule one level cruder: an enrolment that throws must not strand the user either. */
    @Test
    fun `an enrolment that fails outright still lands the user in the app`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository().apply {
            enableThrows = IllegalStateException("no foreground activity to host the prompt")
        }
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onEnrolBiometricChanged(true)
        vm.onSignupClicked()
        runCurrent()

        assertEquals(SignUpNavigation.Success, vm.navigation.receive())
    }

    /** Nothing was asked on a device with no checkbox, so nothing may be answered on its behalf. */
    @Test
    fun `a signup with no checkbox drawn neither enrols nor spends the offer`() = runTest {
        coEvery { signUpUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val biometrics = FakeBiometricUnlockRepository(availability = BiometricAvailability.NoHardware)
        val vm = newVm(biometrics)
        runCurrent()

        vm.fillValid()
        vm.onSignupClicked()
        runCurrent()
        vm.navigation.receive()

        assertTrue(biometrics.enableCalls.isEmpty())
        assertTrue(biometrics.offered.isEmpty())
    }
}

private class FakeBiometricUnlockRepository(
    private val availability: BiometricAvailability = BiometricAvailability.Available,
) : BiometricUnlockRepository {
    private val enrolledUsers = mutableSetOf<String>()

    /** Accounts whose one-time enrolment offer has been spent. */
    val offered = mutableSetOf<String>()

    /** Every (username, password) pair enrolment was attempted with, in order. */
    val enableCalls = mutableListOf<Pair<String, String>>()

    /** Set to make the system prompt refuse — a cancel, a lockout, a mismatched password. */
    var enableFailure: Outcome.Error? = null

    /** Set to make the enrolment call blow up rather than answer. */
    var enableThrows: Exception? = null

    override suspend fun biometricUnlockState(username: String) =
        BiometricUnlockState(availability = availability, enrolled = username in enrolledUsers)

    override suspend fun biometricAvailability() = availability

    override suspend fun enable(username: String, password: String): Outcome<Unit> {
        enableCalls += username to password
        enableThrows?.let { throw it }
        enableFailure?.let { return it }
        enrolledUsers += username
        return Outcome.Success(Unit)
    }

    override suspend fun disable(username: String) {
        enrolledUsers -= username
    }

    override suspend fun enrolmentOffered(username: String) = username in offered

    override suspend fun recordEnrolmentOffered(username: String) {
        offered += username
    }
}

/** The account a successful signup has just recorded — what the offer use cases resolve. */
private object SignedInUserPreferences : UserPreferences {
    override suspend fun getUser(): AppUser = AppUser.LoggedIn("mia", Password(hash = "h", salt = "s"))

    override suspend fun upsert(user: AppUser) = unsupported()
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing = throw UnsupportedOperationException("not used by this test")
}
