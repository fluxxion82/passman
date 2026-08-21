package ai.passman.domain.user

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.FakePgpRepository
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.runTest

/**
 * Account creation refuses a username that is not usable as a path component — **here**, not only on
 * the sign-up screen.
 *
 * The username is a path component: every artifact is `keystore/<user>/…` or `pgp/<user>/…`, built by
 * string concatenation, with siblings `<user>.conflicts`, `<user>.lock` and `<user>.unbundle-staging`.
 * "This name is safe to build paths from" is therefore an invariant of *creating an account*, not a
 * field-validation rule the presentation layer happens to apply.
 *
 * For one commit the check lived only in `SignUpViewModel`, which meant any other caller of this use
 * case could bootstrap an account named `./alice` or `con` — and a comment in
 * `IdentityStoreDisplaceableTest` asserting such an account could no longer be created was false.
 * These pin it at the layer that owns the operation.
 */
class SignUpUserTest {

    @Test
    fun refusesAUsernameThatIsNotUsableAsAPathComponent() = runTest {
        listOf(
            "./alice",       // defeats the basename-keyed sync exclusion list
            "team/a",        // nests one account's directory inside another's
            "con",           // not a filename on Windows, at any path
            "alice.lock",    // claims the path another account uses for its lock file
            "café",     // two spellings, one file on APFS and NTFS
            "a".repeat(ValidateSignUpCredentials.MAX_USERNAME_LENGTH + 1),
        ).forEach { username ->
            val repository = RecordingUserRepository()

            val outcome = signUpUser(repository)(SignUpUser.SignUpRequest.Standard(username, STRONG_PASSWORD))

            assertIs<Outcome.Error>(outcome, "\"$username\" must not create an account")
            assertEquals(AuthFailure.SignupFailure, outcome.cause)
            assertNull(
                repository.signedUpAs,
                "\"$username\" must be refused before the repository is asked to create anything",
            )
        }
    }

    /**
     * The control: an ordinary username reaches the repository, and reaches it **trimmed**.
     *
     * The trim is the load-bearing half of an agreement — this use case validates `trim()`ed input
     * and must store the same thing, or a name accepted as `alice` would be created as `alice `,
     * whose trailing space Windows folds onto a different account's paths.
     *
     * The repository returns an error so the flow stops there; what happens after a successful
     * creation is another test's business.
     */
    @Test
    fun passesAnOrdinaryUsernameThroughTrimmed() = runTest {
        val repository = RecordingUserRepository()

        signUpUser(repository)(SignUpUser.SignUpRequest.Standard("  alice  ", STRONG_PASSWORD))

        assertEquals("alice", repository.signedUpAs, "the trimmed name is what gets created")
    }

    /**
     * Password policy stays the screen's business.
     *
     * This use case refuses what would make the storage layout unsafe; it does not police credential
     * strength, and a caller that legitimately creates an account with a weak password — a test
     * fixture, a future import path — must not be blocked by a rule that belongs to a form.
     */
    @Test
    fun doesNotEnforcePasswordPolicy() = runTest {
        val repository = RecordingUserRepository()

        signUpUser(repository)(SignUpUser.SignUpRequest.Standard("alice", "short"))

        assertEquals("alice", repository.signedUpAs, "a weak password is not this use case's refusal to make")
    }

    private fun signUpUser(repository: UserRepository) = SignUpUser(
        repository = repository,
        validateSignUpCredentials = ValidateSignUpCredentials(),
        userPreferences = FakeLoggedInUserPreferences(),
        userEventPersistence = SilentUserEvents(),
        getUserState = GetUserState(FakeLoggedInUserPreferences(), SilentUserEvents()),
        importDeveloperKey = ImportDeveloperKey(FakePgpRepository(), SilentPgpEvents()),
    )

    /** Records the name it was asked to create, and refuses, so the flow stops at the repository. */
    private class RecordingUserRepository : UserRepository {
        var signedUpAs: String? = null

        override suspend fun signup(username: String, password: String): Outcome<AppUser> {
            signedUpAs = username
            return Outcome.Error("not this test's business", AuthFailure.SignupFailure)
        }

        override suspend fun login(username: String, password: String): Outcome<AppUser> =
            throw UnsupportedOperationException("login")

        override suspend fun bioLogin(username: String): Outcome<AppUser> =
            throw UnsupportedOperationException("bioLogin")

        override suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser> =
            throw UnsupportedOperationException("changeUserPassword")

        override suspend fun verifyMasterPassword(username: String, password: String): Boolean =
            throw UnsupportedOperationException("verifyMasterPassword")

        override suspend fun logout() = throw UnsupportedOperationException("logout")
    }

    private class SilentUserEvents : UserEventPersistence {
        override fun events(): Flow<UserEvent> = emptyFlow()
        override suspend fun update(event: UserEvent) = Unit
    }

    private class SilentPgpEvents : PgpEventPersistence {
        override fun events(): Flow<PgpEvent> = emptyFlow()
        override suspend fun update(event: PgpEvent) = Unit
    }

    private companion object {
        const val STRONG_PASSWORD = "Tr0ub4dor&3-correct-horse"
    }
}
