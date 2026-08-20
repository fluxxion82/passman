package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences

/**
 * Switch biometric unlock on or off for the signed-in account.
 *
 * The account is resolved here rather than passed in, deliberately: enrolment stores a copy of a
 * master password, and letting a caller name the account it belongs to is one typo away from
 * sealing one account's password under another account's key. Nobody outside a session has any
 * business enrolling, so the only reachable answer is "whoever is signed in".
 */
class SetBiometricUnlock(
    private val repository: BiometricUnlockRepository,
    private val userPreferences: UserPreferences,
) : Usecase<SetBiometricUnlock.Request, Outcome<Unit>> {

    sealed interface Request {
        /**
         * [password] is the master password, re-typed. It is verified against the stored credential
         * before anything is wrapped — a wrapped copy of the *wrong* string is an enrolment that
         * silently never works, discovered only at the next unlock.
         */
        data class Enable(val password: String) : Request
        data object Disable : Request
    }

    override suspend fun invoke(param: Request): Outcome<Unit> {
        val username = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName
            ?: return Outcome.Error("Not signed in", AuthFailure.GeneralAuthFailure("not signed in"))

        return when (param) {
            is Request.Enable -> repository.enable(username, param.password)
            Request.Disable -> {
                repository.disable(username)
                Outcome.Success(Unit)
            }
        }
    }
}
