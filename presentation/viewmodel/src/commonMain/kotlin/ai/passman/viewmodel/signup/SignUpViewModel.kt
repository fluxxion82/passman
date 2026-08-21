package ai.passman.viewmodel.signup

import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.GetBiometricAvailability
import ai.passman.domain.user.RecordBiometricUnlockOffered
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.SignUpUser
import ai.passman.domain.user.ValidateSignUpCredentials
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.PasswordStrength
import ai.passman.logging.KLogger
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.signup.SignUpNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

open class SignUpViewModel(
    private val signUpUser: SignUpUser,
    private val validateSignUpCredentials: ValidateSignUpCredentials,
    private val getBiometricAvailability: GetBiometricAvailability,
    private val setBiometricUnlock: SetBiometricUnlock,
    private val recordBiometricUnlockOffered: RecordBiometricUnlockOffered,
) : BaseViewModel() {
    val navigation = Channel<SignUpNavigation>()

    val username = MutableStateFlow("")
    val password = MutableStateFlow("")
    val confirmPassword = MutableStateFlow("")

    val isLoading = MutableStateFlow(false)

    /**
     * Whether the form draws the biometric checkbox at all.
     *
     * Read once at startup and never per-account: there is no account yet, so the only question
     * that can be answered here is what the device can do. Starts false so a device that turns out
     * to have no sensor never flashes a checkbox it is about to take away; desktop reports
     * [BiometricAvailability.NoHardware] and stays here forever.
     */
    val biometricOfferable = MutableStateFlow(false)

    /**
     * The checkbox itself: intent, captured while the user is already filling the form.
     *
     * Nothing acts on it until the account exists. It is deliberately not part of
     * [SignUpUser.SignUpRequest] — that sealed type is single-variant on purpose, because a
     * biometric prompt inside the account bootstrap would sit in the middle of a rollback contract
     * that has to run to completion. This is the intent; [settleBiometricIntent] is the action, and it
     * runs after the bootstrap has committed.
     */
    val enrolBiometric = MutableStateFlow(false)

    init {
        viewModelScope.launch {
            biometricOfferable.value = try {
                getBiometricAvailability() == BiometricAvailability.Available
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (failure: Exception) {
                // A checkbox is a convenience; a platform read that fails must not take down the
                // only screen a new user can reach.
                KLogger.e(failure) { "biometric availability unavailable" }
                false
            }
        }
    }

    // The meter rates what will actually be stored, so it sees the same trimmed value the
    // validation gate and SignUpUser use.
    val passwordStrength: StateFlow<PasswordStrength> =
        combine(username, password) { user, pass ->
            validateSignUpCredentials(user, pass.trim()).strength
        }.stateIn(viewModelScope, SharingStarted.Eagerly, PasswordStrength.Weak)

    fun onUsernameChange(username: String) {
        this.username.value = username
    }

    fun onPasswordChange(password: String) {
        this.password.value = password
    }

    fun onConfirmPasswordChange(confirmPassword: String) {
        this.confirmPassword.value = confirmPassword
    }

    fun onEnrolBiometricChanged(enrol: Boolean) {
        enrolBiometric.value = enrol
    }

    fun onSignupClicked() {
        if (isLoading.value) return
        viewModelScope.launch {
            if (username.value.isEmpty() || password.value.isEmpty()) {
                navigation.send(SignUpNavigation.MissingInformation)
                return@launch
            }
            // SignUpUser trims both fields before storing; validate what will actually be stored.
            val validation = validateSignUpCredentials(username.value, password.value.trim())
            if (!validation.acceptable) {
                navigation.send(SignUpNavigation.InvalidCredentials(validation.issues.first().message()))
                return@launch
            }
            if (password.value != confirmPassword.value) {
                navigation.send(SignUpNavigation.InvalidCredentials("Passwords do not match"))
                return@launch
            }

            isLoading.value = true
            // No biometric variant. Biometric unlock seals a copy of the master password under a
            // hardware key, and doing that here would mean a system prompt inside the account
            // bootstrap's rollback contract — a prompt the user can sit on indefinitely, in the one
            // stretch of code that must run to completion. The checkbox above captures the
            // intent; settleBiometricIntent() acts on it after this returns, on an account that now
            // exists and whose password can be verified against something stored.
            when (val outcome = signUpUser(SignUpUser.SignUpRequest.Standard(username.value, password.value))) {
                is Outcome.Error -> {
                    when (outcome.cause) {
                        is AuthFailure.AccountAlreadyExists -> navigation.send(SignUpNavigation.AccountExists)
                        else -> navigation.send(SignUpNavigation.SignupError(outcome.message))
                    }
                }
                is Outcome.Success -> {
                    settleBiometricIntent()
                    navigation.send(SignUpNavigation.Success)
                }
            }

            isLoading.value = false
        }
    }

    /**
     * Act on the checkbox, now that there is an account to act on.
     *
     * Runs inside the `isLoading` window on purpose: the enrolment ends in a system prompt, and the
     * form behind it stays disabled and spinning until the prompt is answered, exactly as it does
     * for the signup itself.
     *
     * Nothing here can fail the signup. The account exists, the session is open and the user is
     * authenticated; a prompt they cancelled is a setting they did not get, and holding them on the
     * form for it would be punishing them for trying. Failures are logged and Settings is the
     * retry — the signup screen's snackbar collector suspends until the message is dismissed, so
     * reporting through it would do the one thing this must never do, which is delay the way in.
     */
    private suspend fun settleBiometricIntent() {
        // The checkbox was never drawn, so nothing was asked and there is nothing to answer.
        if (!biometricOfferable.value) return

        if (!enrolBiometric.value) {
            // An unticked box is the same "no" the login dialog exists to collect, given earlier
            // and with less ceremony. Spending the offer here is what stops the next login asking a
            // question this form already asked.
            runCatchingBiometric("record the declined enrolment offer") { recordBiometricUnlockOffered() }
            return
        }

        runCatchingBiometric("enrol") {
            // Trimmed the way SignUpUser trims it before storing the credential, or the sealed copy
            // would be a string this account has never had and every later unlock would fail the
            // credential check. No second password field: this is the string that just created the
            // account, and SetBiometricUnlock still verifies it against what was stored.
            val outcome = setBiometricUnlock(SetBiometricUnlock.Request.Enable(password.value.trim()))
            // A refused prompt leaves the offer unspent deliberately: this user said yes, so the
            // login dialog becomes their retry rather than a repetition of a question they answered.
            if (outcome is Outcome.Error) KLogger.d { "biometric enrolment refused: ${outcome.message}" }
        }
    }

    private suspend fun runCatchingBiometric(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            KLogger.e(failure) { "biometric unlock: could not $what after signup" }
        }
    }

    private fun ValidateSignUpCredentials.Issue.message(): String = when (this) {
        ValidateSignUpCredentials.Issue.UsernameTooShort ->
            "Username must be at least ${ValidateSignUpCredentials.MIN_USERNAME_LENGTH} characters"
        ValidateSignUpCredentials.Issue.UsernameTooLong ->
            "Username must be at most ${ValidateSignUpCredentials.MAX_USERNAME_LENGTH} characters"
        // Says what is allowed rather than what was wrong: the rejected input is a path fragment, a
        // reserved device name or a non-ASCII letter, and explaining why any of those is unsafe would
        // mean explaining the storage layout to someone filling in a sign-up form. "A-Z" rather than
        // "letters" because the rule really is ASCII — é and 李 are letters and are refused.
        ValidateSignUpCredentials.Issue.UsernameHasIllegalCharacters ->
            "Username can use A-Z, 0-9, and . _ - between them"
        ValidateSignUpCredentials.Issue.PasswordTooShort ->
            "Master password must be at least ${ValidateSignUpCredentials.MIN_PASSWORD_LENGTH} characters"
        ValidateSignUpCredentials.Issue.PasswordContainsUsername ->
            "Password must not contain your username"
        ValidateSignUpCredentials.Issue.PasswordSingleCharacter ->
            "Password can't be one repeated character"
    }
}
