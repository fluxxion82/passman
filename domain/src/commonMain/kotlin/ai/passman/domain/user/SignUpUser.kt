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

class SignUpUser(
    private val repository: UserRepository,
    private val userPreferences: UserPreferences,
    private val userEventPersistence: UserEventPersistence,
    private val getUserState: GetUserState,
    private val importDeveloperKey: ImportDeveloperKey,
) : Usecase<SignUpUser.SignUpRequest, Outcome<UserState>> {
    /**
     * Only one way to sign up. The biometric variant is gone: biometric unlock stores a copy of a
     * master password under a hardware key, and doing that from inside `bootstrapAccount` would put
     * a system prompt — which the user can sit on, or dismiss — in the middle of a rollback
     * contract that has to run to completion. Enrolment is a settings action on an account that
     * already exists.
     */
    sealed class SignUpRequest {
        data class Standard(val email: String, val password: String) : SignUpRequest()
    }
    override suspend fun invoke(param: SignUpRequest): Outcome<UserState> {
        return when (
            val outcome = when (param) {
                is SignUpRequest.Standard -> repository.signup(
                    username = param.email.trim(),
                    password = param.password.trim(),
                )
            }
        ) {
            is Outcome.Success -> {
                userPreferences.upsert(outcome.value)
                userEventPersistence.update(UserEvent.LoginChanged(outcome.value))
                importBundledDeveloperKey()
                Outcome.Success(getUserState().also { userPreferences.setUserState(it) })
            }
            is Outcome.Error -> outcome //UserState.Anonymous
        }
    }

    /**
     * The only post-signup step, composed here — AFTER the repository's bootstrapAccount has fully
     * succeeded, never inside its rollback contract. A failure is non-fatal and must never fail the
     * signup that just succeeded, so the whole attempt is capped by [withTimeoutOrNull] — its own
     * deadline returns null instead of throwing, while an OUTER cancellation still surfaces as a
     * CancellationException and is rethrown, not swallowed.
     *
     * A new account starts with no keystore and no PGP rings, deliberately: anything created here
     * would carry a fixed filename, and a second device signing up under the same profile would
     * mint a different file under that same name for the first sync to overwrite. The user creates
     * what they need on the Create screens, and a second device inherits it by syncing.
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
            // The use case / repository already logged the cause; the signup outcome stands.
        }
    }

    private companion object {
        /** A stalled volume must not hold the signup result hostage. */
        val DEVELOPER_KEY_IMPORT_TIMEOUT = 5.seconds
    }
}
