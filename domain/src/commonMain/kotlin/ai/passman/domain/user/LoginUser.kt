package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withTimeoutOrNull

class LoginUser(
    private val repository: UserRepository,
    private val userPreferences: UserPreferences,
    private val userEventPersistence: UserEventPersistence,
    private val getUserState: GetUserState,
    private val importDeveloperKey: ImportDeveloperKey,
) : Usecase<LoginUser.LoginRequest, Outcome<UserState>> {

    sealed class LoginRequest {
        /** `username`, not `email` — the login field is labelled Username. See [SignUpUser]. */
        data class Standard(val username: String, val password: String) : LoginRequest()

        /**
         * No password field, and that absence is the feature: the master password comes out of the
         * account's biometric enrolment, so there is nothing for a caller to pass and no way for
         * this path to quietly fall back to something the user typed.
         */
        data class BioAuth(val username: String) : LoginRequest()
    }

    override suspend fun invoke(param: LoginRequest): Outcome<UserState> {
        return when (
            val outcome = when (param) {
                is LoginRequest.BioAuth -> repository.bioLogin(param.username.trim())
                is LoginRequest.Standard -> repository.login(param.username.trim(), param.password.trim())
            }
        ) {
            is Outcome.Success -> {
                userPreferences.upsert(outcome.value)
                userEventPersistence.update(UserEvent.LoginChanged(outcome.value))
                importBundledDeveloperKey()

                Outcome.Success(getUserState().also { userPreferences.setUserState(it) })
            }
            is Outcome.Error -> outcome
        }
    }

    /**
     * Post-login work, composed here — AFTER the account is fully bootstrapped, never inside
     * bootstrapAccount's rollback contract. Once per account; a failure is non-fatal and must
     * never block the login that just succeeded, so the whole attempt is capped by
     * [withTimeoutOrNull] — its own deadline returns null instead of throwing, while an OUTER
     * cancellation still surfaces as a CancellationException and is rethrown, not swallowed.
     *
     * Nothing else hangs off a successful login. Keys and keystores are created by the user on the
     * Create screens; the app provisions no artifacts of its own, so two devices can no longer mint
     * different files under one name and overwrite each other on the first sync.
     */
    private suspend fun importBundledDeveloperKey() = nonFatal(DEVELOPER_KEY_IMPORT_TIMEOUT) {
        importDeveloperKey(ImportDeveloperKey.Mode.OncePerAccount)
    }

    private suspend fun nonFatal(timeout: Duration, block: suspend () -> Unit) {
        try {
            withTimeoutOrNull(timeout) { block() }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // The use case / repository already logged the cause; the login outcome stands.
        }
    }

    private companion object {
        /** A stalled volume must not hold the login result hostage. */
        val DEVELOPER_KEY_IMPORT_TIMEOUT = 5.seconds
    }
}
