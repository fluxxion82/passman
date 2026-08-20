package ai.passman.viewmodel.signup

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.SignUpUser
import ai.passman.domain.user.ValidateSignUpCredentials
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.PasswordStrength
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.signup.SignUpNavigation
import androidx.lifecycle.viewModelScope
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
) : BaseViewModel() {
    val navigation = Channel<SignUpNavigation>()

    val username = MutableStateFlow("")
    val password = MutableStateFlow("")
    val confirmPassword = MutableStateFlow("")

    val isLoading = MutableStateFlow(false)

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
            // stretch of code that must run to completion. It is a settings action on an account
            // that already exists, where the password can be verified against something stored.
            when (val outcome = signUpUser(SignUpUser.SignUpRequest.Standard(username.value, password.value))) {
                is Outcome.Error -> {
                    when (outcome.cause) {
                        is AuthFailure.AccountAlreadyExists -> navigation.send(SignUpNavigation.AccountExists)
                        else -> navigation.send(SignUpNavigation.SignupError(outcome.message))
                    }
                }
                is Outcome.Success -> navigation.send(SignUpNavigation.Success)
            }

            isLoading.value = false
        }
    }

    private fun ValidateSignUpCredentials.Issue.message(): String = when (this) {
        ValidateSignUpCredentials.Issue.UsernameTooShort ->
            "Username must be at least ${ValidateSignUpCredentials.MIN_USERNAME_LENGTH} characters"
        ValidateSignUpCredentials.Issue.PasswordTooShort ->
            "Master password must be at least ${ValidateSignUpCredentials.MIN_PASSWORD_LENGTH} characters"
        ValidateSignUpCredentials.Issue.PasswordContainsUsername ->
            "Password must not contain your username"
        ValidateSignUpCredentials.Issue.PasswordSingleCharacter ->
            "Password can't be one repeated character"
    }
}
