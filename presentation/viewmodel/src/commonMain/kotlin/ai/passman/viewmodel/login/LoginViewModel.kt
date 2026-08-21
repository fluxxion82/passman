package ai.passman.viewmodel.login

import ai.passman.logging.KLogger
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.domain.user.OfferBiometricUnlock
import ai.passman.domain.user.SetBiometricUnlock
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
    private val offerBiometricUnlock: OfferBiometricUnlock,
    private val setBiometricUnlock: SetBiometricUnlock,
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
     * The one-time "unlock with your fingerprint next time?" dialog, raised between a successful
     * password login and the navigation into the app.
     *
     * It lives here rather than after the jump because this is the last frame that still holds the
     * typed plaintext — once [ai.passman.domain.user.models.AppUser.LoggedIn] is the only record of
     * the account, the password is a hash and a salt and enrolment would have to ask for it again.
     */
    val biometricOfferVisible = MutableStateFlow(false)

    /** Set while the system prompt raised by the offer is up. */
    val isEnrollingBiometric = MutableStateFlow(false)

    /**
     * Cancelled and replaced on every username edit. Without it, a fast typist leaves several reads
     * in flight and the flag ends up reflecting whichever preference read finished last rather than
     * the name on screen.
     */
    private var biometricStateJob: Job? = null

    /**
     * Raised at most once per screen. An enrolled user should meet the system prompt on arrival
     * rather than having to find the fingerprint icon — but exactly once, because the two obvious
     * ways to get this wrong are both worse than not doing it. Re-raising after a cancel traps the
     * user in a prompt they are trying to dismiss, and raising it on a username *edit* would fire a
     * full-screen system dialog while they are still typing. So it fires only from the initial load,
     * and the icon remains the way to ask for it again.
     */
    private var biometricPromptRaised = false

    /**
     * Set by the first edit of either field. The remembered-username read is asynchronous, so a user
     * who starts typing before it lands would otherwise be interrupted by a full-screen system
     * prompt mid-keystroke — the arrival prompt is for someone who arrived and waited, not for
     * someone already at work.
     */
    private var userHasTyped = false

    init {
        viewModelScope.launch {
            // A suggestion list is a convenience; a preferences read failure must not
            // take down the one screen the user cannot navigate away from.
            val loaded = runCatching { getKnownUsernames() }
                .onFailure { KLogger.e(it) { "known usernames unavailable" } }
                .getOrDefault(emptyList())
            knownUsernames.value = loaded
            if (username.isEmpty()) loaded.firstOrNull()?.let { username = it }
            refreshBiometricUnlock(autoPrompt = true)
        }
    }

    fun onUsernameChange(username: String) {
        userHasTyped = true
        this.username = username
        refreshBiometricUnlock()
    }

    fun onPasswordChange(password: String) {
        userHasTyped = true
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
                            // [requiresPassword] is also exactly "this path typed a password", and
                            // that is the only path that can offer enrolment: the biometric one has
                            // no plaintext to seal and is enrolled by definition. When the offer is
                            // raised the dialog owns the navigation instead — see
                            // [onBiometricOfferAccepted] and [onBiometricOfferDeclined].
                            if (!(requiresPassword && raiseBiometricOffer())) {
                                navigation.send(LoginNavigation.GoToHome)
                            }
                        }
                        is UserState.PendingActive -> Unit
                    }
                }
            }

            isLoading.value = false
        }
    }

    /**
     * Accepting the offer: seal the password the user typed a moment ago.
     *
     * No second password field, deliberately — this is the difference between the offer and the
     * settings toggle, and the reason the offer is worth having. Nothing is taken on trust for it:
     * [SetBiometricUnlock] still verifies the string against the stored credential before anything
     * is wrapped.
     */
    fun onBiometricOfferAccepted() {
        if (isEnrollingBiometric.value) return
        isEnrollingBiometric.value = true
        viewModelScope.launch {
            try {
                // Trimmed the way LoginUser trims it before logging in, or the sealed copy would be
                // a string this account has never had and every later unlock would fail the
                // credential check.
                val outcome = setBiometricUnlock(SetBiometricUnlock.Request.Enable(password.trim()))
                if (outcome is Outcome.Error) KLogger.d { "biometric enrolment refused: ${outcome.message}" }
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (failure: Exception) {
                KLogger.e(failure) { "biometric enrolment failed" }
            } finally {
                isEnrollingBiometric.value = false
                biometricOfferVisible.value = false
            }
            // Whatever the prompt did. The user authenticated before this dialog existed, so a
            // cancelled or failed enrolment is a setting they did not get, not a login they did not
            // make — holding them on this screen for it would be punishing them for trying.
            navigation.send(LoginNavigation.GoToHome)
        }
    }

    /** "Not now". The account's one offer is already spent — see [OfferBiometricUnlock]. */
    fun onBiometricOfferDeclined() {
        if (isEnrollingBiometric.value) return
        biometricOfferVisible.value = false
        viewModelScope.launch { navigation.send(LoginNavigation.GoToHome) }
    }

    /**
     * @return true when the dialog is now up and the caller must NOT navigate. A failure to decide
     * is answered "no": discovering a feature is never worth failing a login that succeeded.
     */
    private suspend fun raiseBiometricOffer(): Boolean {
        val offer = try {
            offerBiometricUnlock()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            KLogger.e(failure) { "biometric enrolment offer unavailable" }
            false
        }
        biometricOfferVisible.value = offer
        return offer
    }

    private fun refreshBiometricUnlock(autoPrompt: Boolean = false) {
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

            if (autoPrompt && canBioAuth.value && !biometricPromptRaised && !userHasTyped && !isLoading.value) {
                // Latched before the call, not after: onBioAuth suspends into a system prompt, and
                // anything that re-entered here meanwhile would raise a second one.
                biometricPromptRaised = true
                onBioAuth()
            }
        }
    }
}
