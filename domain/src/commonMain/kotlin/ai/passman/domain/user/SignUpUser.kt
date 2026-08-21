package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.user.exception.AuthFailure
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
    private val validateSignUpCredentials: ValidateSignUpCredentials,
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
        /**
          * `username`, not `email`. The field it carries is labelled **Username** on the sign-up
          * screen and is used as a **path component** — `keystore/<user>/`, `pgp/<user>/` — and since
          * the character rule landed it rejects an address outright. The old name outlived whatever
          * it once described and sent a reviewer looking for a bug that was not there.
          */
        data class Standard(val username: String, val password: String) : SignUpRequest()
    }
    override suspend fun invoke(param: SignUpRequest): Outcome<UserState> {
        // Checked here, not only on the sign-up screen. The username is a path component — every
        // artifact this app owns is `keystore/<user>/…` or `pgp/<user>/…` built by concatenation — so
        // "this name is safe to build paths from" is an invariant of *creating an account*, not a
        // field-validation rule the presentation layer happens to apply. With it only in
        // `SignUpViewModel`, any other caller of this use case bootstrapped an account named `./alice`
        // or `con`, and a comment elsewhere claiming such an account could no longer be created was
        // simply false.
        //
        // Only the username issues are enforced. Password strength is credential policy and stays the
        // screen's business; this use case refuses what would make the storage layout unsafe, which is
        // the part no caller may opt out of.
        val username = (param as SignUpRequest.Standard).username.trim()
        val usernameIssues = validateSignUpCredentials(username, param.password.trim()).issues
            .filter { it in USERNAME_ISSUES }
        if (usernameIssues.isNotEmpty()) {
            return Outcome.Error("unusable username: ${usernameIssues.first()}", AuthFailure.SignupFailure)
        }
        return when (
            val outcome = when (param) {
                is SignUpRequest.Standard -> repository.signup(
                    username = username,
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

        /**
         * The issues that describe the *name*, as opposed to the password.
         *
         * Listed rather than inferred so that adding a password rule to the validator cannot silently
         * start failing account creation from callers that never asked this use case to police
         * credential strength.
         */
        val USERNAME_ISSUES = setOf(
            ValidateSignUpCredentials.Issue.UsernameTooShort,
            ValidateSignUpCredentials.Issue.UsernameTooLong,
            ValidateSignUpCredentials.Issue.UsernameHasIllegalCharacters,
        )
    }
}
