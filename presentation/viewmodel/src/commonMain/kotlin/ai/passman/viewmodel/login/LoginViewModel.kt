package ai.passman.viewmodel.login

import ai.passman.logging.KLogger
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.login.LoginNavigation
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewModelScope
import kotlin.time.Duration
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class LoginViewModel(
    private val loginUser: LoginUser,
    private val getKnownUsernames: GetKnownUsernames,
    private val loginAttemptThrottle: LoginAttemptThrottle,
    private val getBiometricUnlockState: GetBiometricUnlockState,
) : BaseViewModel() {
    val navigation = Channel<LoginNavigation>(Channel.RENDEZVOUS)

    // https://issuetracker.google.com/issues/160257648
    // https://developer.android.com/jetpack/compose/text/user-input#state-practices
    var username by mutableStateOf("")
        private set
    var password by mutableStateOf("")
        private set

    val isLoading = MutableStateFlow(false)
    val knownUsernames = MutableStateFlow<List<String>>(emptyList())

    /**
     * Whether the biometric button is worth showing *for the name currently in the field*.
     *
     * Enrolment is per account, so this is not a device capability that can be read once at
     * startup — a device with two accounts on it can unlock one of them and not the other, and
     * offering the button for the wrong one is a prompt that can only end in a failure message.
     */
    val canBioAuth = MutableStateFlow(false)

    /**
     * Cancelled and replaced on every username edit. Without it, a fast typist leaves several reads
     * in flight and the flag ends up reflecting whichever preference read finished last rather than
     * the name on screen.
     */
    private var biometricStateJob: Job? = null

    init {
        viewModelScope.launch {
            // A suggestion list is a convenience; a preferences read failure must not
            // take down the one screen the user cannot navigate away from.
            val loaded = runCatching { getKnownUsernames() }
                .onFailure { KLogger.e(it) { "known usernames unavailable" } }
                .getOrDefault(emptyList())
            knownUsernames.value = loaded
            if (username.isEmpty()) loaded.firstOrNull()?.let { username = it }
            refreshBiometricUnlock()
        }
    }

    fun onUsernameChange(username: String) {
        this.username = username
        refreshBiometricUnlock()
    }

    fun onPasswordChange(password: String) {
        this.password = password
    }

    fun onLogin() {
        attemptLogin(requiresPassword = true) { LoginUser.LoginRequest.Standard(username, password) }
    }

    fun onBioAuth() {
        attemptLogin(requiresPassword = false) { LoginUser.LoginRequest.BioAuth(username) }
    }

    /**
     * [requiresPassword] is false for the biometric path and that is the entire point of it: the
     * password field is empty there by design, because the master password comes out of the
     * keystore. The empty-field guard below is the typed path's, and applying it to both is what
     * made the biometric button unreachable — it rejected the attempt before the prompt could run.
     */
    private fun attemptLogin(requiresPassword: Boolean, request: () -> LoginUser.LoginRequest) {
        if (isLoading.value) return
        viewModelScope.launch {
            if (username.isEmpty() || (requiresPassword && password.isEmpty())) {
                navigation.send(LoginNavigation.LoginError("Missing information"))
                return@launch
            }
            val wait = loginAttemptThrottle.cooldownRemaining()
            if (wait > Duration.ZERO) {
                val seconds = wait.inWholeSeconds.coerceAtLeast(1)
                navigation.send(LoginNavigation.LoginError("Too many failed attempts. Try again in ${seconds}s"))
                return@launch
            }

            isLoading.value = true
            when (val outcome = loginUser(request())) {
                is Outcome.Error -> {
                    // This throttle exists to stop the screen being a free master-password guessing
                    // oracle, and a biometric failure is not a guess: the platform rate-limits the
                    // sensor itself, and a dismissed prompt is not an attempt at all. Counting them
                    // would let five cancelled prompts lock a user out of their own password field.
                    if (outcome.cause !is AuthFailure.BiometricFailure) loginAttemptThrottle.recordFailure()
                    navigation.send(LoginNavigation.LoginError(outcome.message))
                    // An invalidated enrolment has just been cleared underneath us; the button has
                    // to stop offering something that no longer exists.
                    refreshBiometricUnlock()
                }
                is Outcome.Success -> {
                    when (outcome.value) {
                        UserState.Anonymous -> Unit
                        UserState.LoggedIn -> {
                            loginAttemptThrottle.recordSuccess()
                            KLogger.d {
                                "logged in"
                            }
                            navigation.send(LoginNavigation.GoToHome)
                        }
                        is UserState.PendingActive -> Unit
                    }
                }
            }

            isLoading.value = false
        }
    }

    private fun refreshBiometricUnlock() {
        biometricStateJob?.cancel()
        val name = username
        biometricStateJob = viewModelScope.launch {
            val state = try {
                getBiometricUnlockState(GetBiometricUnlockState.Request.ForUsername(name))
            } catch (cancellation: CancellationException) {
                // A newer edit owns the answer now. Rethrown rather than swallowed, or this stale
                // read would write its (false) result over the fresh one.
                throw cancellation
            } catch (failure: Exception) {
                KLogger.e(failure) { "biometric unlock state unavailable" }
                null
            }
            canBioAuth.value = state?.canUnlock == true
        }
    }
}
