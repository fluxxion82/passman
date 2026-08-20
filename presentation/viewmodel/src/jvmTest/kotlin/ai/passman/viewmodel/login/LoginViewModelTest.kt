package ai.passman.viewmodel.login

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.domain.user.OfferBiometricUnlock
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.viewvo.login.LoginNavigation
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
            getBiometricUnlockState = biometricState(),
            offerBiometricUnlock = offerBiometricUnlock(),
            setBiometricUnlock = setBiometricUnlock(),
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
            getBiometricUnlockState = biometricState(),
            offerBiometricUnlock = offerBiometricUnlock(),
            setBiometricUnlock = setBiometricUnlock(),
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
            getBiometricUnlockState = biometricState(),
            offerBiometricUnlock = offerBiometricUnlock(),
            setBiometricUnlock = setBiometricUnlock(),
        )

        viewModel.onUsernameChange("typed")
        runCurrent()

        assertEquals("typed", viewModel.username)
        assertEquals(usernames, viewModel.knownUsernames.value)
    }

    private fun newVm(
        loginUser: LoginUser,
        throttle: LoginAttemptThrottle = LoginAttemptThrottle(timeSource = TestTimeSource()),
        // NoHardware by default — the desktop answer — so the login-mechanics tests below see the
        // plain path. On a device that *could* enrol, a successful password login raises the
        // enrolment offer instead of navigating, which is what the offer tests further down assert.
        biometrics: FakeBiometricUnlockRepository =
            FakeBiometricUnlockRepository(availability = BiometricAvailability.NoHardware),
    ) = LoginViewModel(
        loginUser = loginUser,
        getKnownUsernames = GetKnownUsernames(FakeUserPreferences(emptyList())),
        loginAttemptThrottle = throttle,
        getBiometricUnlockState = biometricState(biometrics),
        offerBiometricUnlock = offerBiometricUnlock(biometrics),
        setBiometricUnlock = setBiometricUnlock(biometrics),
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

    // ---------------------------------------------------------- biometric unlock

    /**
     * The point of the whole feature, asserted as a shape rather than a behaviour: the request that
     * reaches the use case carries a username and *nothing else*.
     *
     * The empty password field is deliberate. `attemptLogin` rejects an empty password before it
     * ever reaches the use case, and that guard is why the biometric button was unreachable — the
     * one path that is supposed to have no typed password was being turned away for not having one.
     */
    @Test
    fun `the biometric path signs in with an empty password field`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        val vm = newVm(loginUser).apply { onPasswordChange("") }

        vm.onBioAuth()
        runCurrent()

        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        coVerify(exactly = 1) { loginUser.invoke(LoginUser.LoginRequest.BioAuth("mia")) }
    }

    /** The typed path keeps its guard — an empty password there is still a mistake. */
    @Test
    fun `the typed path still refuses an empty password`() = runTest {
        val loginUser: LoginUser = mockk(relaxed = true)
        val vm = newVm(loginUser).apply { onPasswordChange("") }

        vm.onLogin()
        runCurrent()

        assertEquals(LoginNavigation.LoginError("Missing information"), vm.navigation.receive())
        coVerify(exactly = 0) { loginUser.invoke(any()) }
    }

    @Test
    fun `the button is offered only for a username with an enrolment this device can use`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply { enrolledUsers += "mia" }
        val vm = newVm(mockk(relaxed = true), biometrics = biometrics)
        runCurrent()

        assertTrue(vm.canBioAuth.value)

        vm.onUsernameChange("ada")
        runCurrent()
        assertFalse(vm.canBioAuth.value, "ada has no enrolment on this device")

        vm.onUsernameChange("mia")
        runCurrent()
        assertTrue(vm.canBioAuth.value)
    }

    @Test
    fun `the button is withheld when the device itself cannot authenticate`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply {
            enrolledUsers += "mia"
            availability = BiometricAvailability.NotEnrolled
        }
        val vm = newVm(mockk(relaxed = true), biometrics = biometrics)
        runCurrent()

        assertFalse(vm.canBioAuth.value, "an enrolment is useless with no biometric registered to unlock it")
    }

    /**
     * The throttle exists to stop the screen being a free master-password guessing oracle. A
     * dismissed prompt is not a guess, and counting it would let five cancels lock the user out of
     * the password field that is their way back in.
     */
    @Test
    fun `cancelled biometric prompts never spend the password throttle`() = runTest {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns
            Outcome.Error("Biometric unlock was cancelled", AuthFailure.BioAuthCancelled)
        val vm = newVm(loginUser).apply { onPasswordChange("") }

        repeat(6) {
            vm.onBioAuth()
            runCurrent()
            assertEquals(LoginNavigation.LoginError("Biometric unlock was cancelled"), vm.navigation.receive())
            runCurrent()
        }

        // The typed path is still on its first attempt, not locked out.
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("bad password", AuthFailure.InvalidPassword)
        vm.onPasswordChange("pw")
        vm.onLogin()
        runCurrent()
        assertEquals(LoginNavigation.LoginError("bad password"), vm.navigation.receive())
    }

    /** A genuine password failure still counts, biometric feature or not. */
    @Test
    fun `a wrong password on the biometric path still spends the throttle`() = runTest {
        val loginUser: LoginUser = mockk()
        // A wrapped password that no longer verifies — the account's password was changed elsewhere.
        coEvery { loginUser.invoke(any()) } returns Outcome.Error("Password is incorrect", AuthFailure.InvalidPassword)
        val vm = newVm(loginUser).apply { onPasswordChange("") }

        repeat(5) {
            vm.onBioAuth()
            runCurrent()
            vm.navigation.receive()
            runCurrent()
        }

        vm.onBioAuth()
        runCurrent()
        val nav = vm.navigation.receive()
        assertTrue(nav is LoginNavigation.LoginError && nav.message.startsWith("Too many failed attempts"))
    }

    /**
     * An invalidated enrolment is cleared by the layer that discovered it, so the button has to stop
     * offering it without waiting for the screen to be rebuilt.
     */
    @Test
    fun `an invalidated enrolment takes the button away`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply { enrolledUsers += "mia" }
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } coAnswers {
            biometrics.enrolledUsers -= "mia" // what BiometricUnlock does on PermanentlyInvalidated
            Outcome.Error("Biometric unlock was turned off", AuthFailure.BioAuthInvalidated)
        }
        val vm = newVm(loginUser, biometrics = biometrics).apply { onPasswordChange("") }
        runCurrent()
        assertTrue(vm.canBioAuth.value)

        vm.onBioAuth()
        runCurrent()
        vm.navigation.receive()
        runCurrent()

        assertFalse(vm.canBioAuth.value)
    }

    // ------------------------------------------- the one-time enrolment offer

    /** A view model whose login always succeeds, so the tests below are only about the offer. */
    private fun offeringVm(biometrics: FakeBiometricUnlockRepository): LoginViewModel {
        val loginUser: LoginUser = mockk()
        coEvery { loginUser.invoke(any()) } returns Outcome.Success(UserState.LoggedIn)
        return newVm(loginUser, biometrics = biometrics)
    }

    /**
     * The whole point of the feature. Biometric unlock is otherwise reachable only through a
     * settings toggle nobody goes looking for, so an eligible account is asked once — and asked
     * here, in the last frame that still holds the password the user typed.
     */
    @Test
    fun `a password login offers enrolment on the way into the app`() = runTest {
        val biometrics = FakeBiometricUnlockRepository()
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()

        assertTrue(vm.biometricOfferVisible.value)
        assertTrue(
            vm.navigation.tryReceive().isFailure,
            "the dialog owns the navigation until it is answered",
        )
    }

    @Test
    fun `an account that is already enrolled is not offered`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply { enrolledUsers += "mia" }
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()

        assertFalse(vm.biometricOfferVisible.value)
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
    }

    /** NoHardware is the desktop answer, so this is also "the dialog never appears on desktop". */
    @Test
    fun `a device that cannot authenticate is not offered`() = runTest {
        val biometrics = FakeBiometricUnlockRepository(availability = BiometricAvailability.NoHardware)
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()

        assertFalse(vm.biometricOfferVisible.value)
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        assertTrue(biometrics.offered.isEmpty(), "an offer that cannot be made must not be spent")
    }

    /**
     * "No" has to stick. A prompt that returns at every sign-in is worse than one that never
     * appears, because the second is only a missed feature and the first is the app arguing.
     */
    @Test
    fun `declining is remembered, so a later login goes straight in`() = runTest {
        val biometrics = FakeBiometricUnlockRepository()
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()
        assertTrue(vm.biometricOfferVisible.value)

        vm.onBiometricOfferDeclined()
        runCurrent()
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        runCurrent()
        assertFalse(vm.biometricOfferVisible.value)

        vm.onLogin()
        runCurrent()

        assertFalse(vm.biometricOfferVisible.value, "this account has already been asked")
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        assertTrue(biometrics.enableCalls.isEmpty(), "declining must not enrol anything")
    }

    /** Declining is not a failed login: the user authenticated before the dialog existed. */
    @Test
    fun `declining still lands the user in the app`() = runTest {
        val vm = offeringVm(FakeBiometricUnlockRepository())

        vm.onLogin()
        runCurrent()
        vm.onBiometricOfferDeclined()
        runCurrent()

        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
    }

    /** Asking somebody who unlocked with a fingerprint whether they want fingerprint unlock. */
    @Test
    fun `a biometric login is never offered enrolment`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply { enrolledUsers += "mia" }
        val vm = offeringVm(biometrics).apply { onPasswordChange("") }

        vm.onBioAuth()
        runCurrent()

        assertFalse(vm.biometricOfferVisible.value)
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        assertTrue(biometrics.offered.isEmpty(), "the offer was never even considered")
    }

    /**
     * The difference between this dialog and the settings toggle, and the reason it is worth
     * having: the password is already in hand, so there is no second field to fill in. It is
     * trimmed the way LoginUser trims it, or the sealed copy would be a string this account has
     * never had and every later unlock would fail the credential check.
     */
    @Test
    fun `accepting enrols with the password already typed`() = runTest {
        val biometrics = FakeBiometricUnlockRepository()
        val vm = offeringVm(biometrics).apply { onPasswordChange("  pw  ") }

        vm.onLogin()
        runCurrent()
        vm.onBiometricOfferAccepted()
        runCurrent()

        assertEquals(listOf("mia" to "pw"), biometrics.enableCalls)
        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        runCurrent()
        assertFalse(vm.biometricOfferVisible.value)
        assertFalse(vm.isEnrollingBiometric.value)
    }

    @Test
    fun `a refused prompt still lands the user in the app`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply {
            enableFailure = Outcome.Error("Biometric unlock was cancelled", AuthFailure.BioAuthCancelled)
        }
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()
        vm.onBiometricOfferAccepted()
        runCurrent()

        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        runCurrent()
        assertFalse(vm.biometricOfferVisible.value)
        assertFalse(vm.isEnrollingBiometric.value)
    }

    /** Same rule one level cruder: even an enrolment that throws must not strand the user. */
    @Test
    fun `an enrolment that fails outright still lands the user in the app`() = runTest {
        val biometrics = FakeBiometricUnlockRepository().apply {
            enableThrows = IllegalStateException("no foreground activity to host the prompt")
        }
        val vm = offeringVm(biometrics)

        vm.onLogin()
        runCurrent()
        vm.onBiometricOfferAccepted()
        runCurrent()

        assertEquals(LoginNavigation.GoToHome, vm.navigation.receive())
        runCurrent()
        assertFalse(vm.isEnrollingBiometric.value)
    }

    private fun biometricState(
        biometrics: FakeBiometricUnlockRepository = FakeBiometricUnlockRepository(),
    ) = GetBiometricUnlockState(biometrics, FakeUserPreferences(emptyList()))

    /** Both offer use cases resolve the account from preferences, so the fake has to be signed in. */
    private fun offerBiometricUnlock(
        biometrics: FakeBiometricUnlockRepository = FakeBiometricUnlockRepository(),
    ) = OfferBiometricUnlock(biometrics, FakeUserPreferences(emptyList()))

    private fun setBiometricUnlock(
        biometrics: FakeBiometricUnlockRepository = FakeBiometricUnlockRepository(),
    ) = SetBiometricUnlock(biometrics, FakeUserPreferences(emptyList()))
}

/** Enrolment is per account, so the fake is keyed by username rather than a single flag. */
private class FakeBiometricUnlockRepository(
    var availability: BiometricAvailability = BiometricAvailability.Available,
) : BiometricUnlockRepository {
    val enrolledUsers = mutableSetOf<String>()

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

private class FakeUserPreferences(
    private val usernames: List<String>,
) : UserPreferences {
    /** The account a successful login has just recorded — what the offer use cases resolve. */
    override suspend fun getUser(): AppUser = AppUser.LoggedIn("mia", Password(hash = "h", salt = "s"))
    override suspend fun upsert(user: AppUser) = unsupported()
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getKnownUsernames(): List<String> = usernames
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing = throw UnsupportedOperationException("not used by this test")
}
