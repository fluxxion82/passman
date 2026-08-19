package ai.passman.viewmodel.signup

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.SignUpUser
import ai.passman.domain.user.ValidateSignUpCredentials
import ai.passman.domain.user.models.PasswordStrength
import ai.passman.viewvo.signup.SignUpNavigation
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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

    private fun newVm() = SignUpViewModel(
        signUpUser = signUpUser,
        validateSignUpCredentials = ValidateSignUpCredentials(),
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
}
