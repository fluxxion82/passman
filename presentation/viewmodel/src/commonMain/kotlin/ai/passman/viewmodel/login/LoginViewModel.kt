package ai.passman.viewmodel.login

import ai.passman.logging.KLogger
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.login.LoginNavigation
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewModelScope
import kotlin.time.Duration
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class LoginViewModel(
    private val loginUser: LoginUser,
    private val getKnownUsernames: GetKnownUsernames,
    private val loginAttemptThrottle: LoginAttemptThrottle,
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

    init {
        viewModelScope.launch {
            // A suggestion list is a convenience; a preferences read failure must not
            // take down the one screen the user cannot navigate away from.
            val loaded = runCatching { getKnownUsernames() }
                .onFailure { KLogger.e(it) { "known usernames unavailable" } }
                .getOrDefault(emptyList())
            knownUsernames.value = loaded
            if (username.isEmpty()) loaded.firstOrNull()?.let { username = it }
        }
    }

    fun onUsernameChange(username: String) {
        this.username = username
    }

    fun onPasswordChange(password: String) {
        this.password = password
    }

    fun onLogin() {
        attemptLogin { LoginUser.LoginRequest.Standard(username, password) }
    }

    fun onBioAuth() {
        attemptLogin { LoginUser.LoginRequest.BioAuth(username, password) }
    }

    private fun attemptLogin(request: () -> LoginUser.LoginRequest) {
        if (isLoading.value) return
        viewModelScope.launch {
            if (username.isEmpty() || password.isEmpty()) {
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
                    loginAttemptThrottle.recordFailure()
                    navigation.send(LoginNavigation.LoginError(outcome.message))
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
}
