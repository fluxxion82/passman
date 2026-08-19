package ai.passman.viewmodel.login

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.viewvo.login.LoginNavigation
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.TestTimeSource
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
class LoginViewModelTest {

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `known usernames load when the view model starts`() = runTest {
        val usernames = listOf("mia", "ada", "zoe")
        val viewModel = LoginViewModel(
            loginUser = mockk(relaxed = true),
            getKnownUsernames = GetKnownUsernames(FakeUserPreferences(usernames)),
            loginAttemptThrottle = LoginAttemptThrottle(timeSource = TestTimeSource()),
        )

        runCurrent()

        assertEquals(usernames, viewModel.knownUsernames.value)
    }

    @Test
    fun `username is prefilled with the last used known username`() = runTest {
        val usernames = listOf("mia", "ada", "zoe")
        val viewModel = LoginViewModel(
            loginUser = mockk(relaxed = true),
            getKnownUsernames = GetKnownUsernames(FakeUserPreferences(usernames)),
            loginAttemptThrottle = LoginAttemptThrottle(timeSource = TestTimeSource()),
        )

        runCurrent()

        assertEquals("mia", viewModel.username)
    }

    @Test
    fun `typed username survives known username loading`() = runTest {
        val usernames = listOf("mia", "ada", "zoe")
        val viewModel = LoginViewModel(
            loginUser = mockk(relaxed = true),
            getKnownUsernames = GetKnownUsernames(FakeUserPreferences(usernames)),
            loginAttemptThrottle = LoginAttemptThrottle(timeSource = TestTimeSource()),
        )

        viewModel.onUsernameChange("typed")
        runCurrent()

        assertEquals("typed", viewModel.username)
        assertEquals(usernames, viewModel.knownUsernames.value)
    }

    private fun newVm(
        loginUser: LoginUser,
        throttle: LoginAttemptThrottle = LoginAttemptThrottle(timeSource = TestTimeSource()),
    ) = LoginViewModel(
        loginUser = loginUser,
        getKnownUsernames = GetKnownUsernames(FakeUserPreferences(emptyList())),
        loginAttemptThrottle = throttle,
    ).apply {
        onUsernameChange("mia")
        onPasswordChange("pw")
    }

    @Test
    fun `second login click while one is in flight is ignored`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } coAnswers {
            delay(5_000)
            Outcome.Success(UserState.LoggedIn)
        }
        val vm = newVm(loginUser)

        vm.onLogin()
        runCurrent()
        vm.onLogin()
        runCurrent()

        advanceUntilIdle()
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        coVerify(exactly = 1) { loginUser.invoke(any()) }
    }

    @Test
    fun `sixth attempt after five failures is blocked without touching the vault`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("bad password", AuthFailure.InvalidPassword)
        val vm = newVm(loginUser)

        repeat(5) {
            vm.onLogin()
            runCurrent()
            assertEquals(LoginNavigation.LoginError("bad password"), vm.navigation.receive())
            runCurrent()
        }

        vm.onLogin()
        runCurrent()

        val nav = vm.navigation.receive()
        assertTrue(nav is LoginNavigation.LoginError && nav.message.startsWith("Too many failed attempts"))
        coVerify(exactly = 5) { loginUser.invoke(any()) }
    }

    @Test
    fun `cooldown message names the wait in seconds`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("bad password", AuthFailure.InvalidPassword)
        val vm = newVm(loginUser)

        repeat(5) {
            vm.onLogin()
            runCurrent()
            vm.navigation.receive()
            runCurrent()
        }

        vm.onLogin()
        runCurrent()

        assertEquals(
            LoginNavigation.LoginError("Too many failed attempts. Try again in 30s"),
            vm.navigation.receive(),
        )
    }

    @Test
    fun `a successful login clears the failure count`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("bad password", AuthFailure.InvalidPassword)
        val vm = newVm(loginUser)

        repeat(4) {
            vm.onLogin()
            runCurrent()
            vm.navigation.receive()
            runCurrent()
        }

        coEvery { loginUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        vm.onLogin()
        runCurrent()
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        runCurrent()

        // The counter reset means the next bad attempt is failure one of five, not the fifth.
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("bad password", AuthFailure.InvalidPassword)
        vm.onLogin()
        runCurrent()
        assertEquals(LoginNavigation.LoginError("bad password"), vm.navigation.receive())
    }
}

private class FakeUserPreferences(
    private val usernames: List<String>,
) : UserPreferences {
    override suspend fun getUser(): AppUser = unsupported()
    override suspend fun upsert(user: AppUser) = unsupported()
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getKnownUsernames(): List<String> = usernames
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing = throw UnsupportedOperationException("not used by this test")
}
