package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences

/**
 * Can this account unlock with a biometric, and is it switched on?
 *
 * Two callers with two different ideas of "this account", which is why the request is a sealed
 * type rather than a nullable username: the login screen is asking about a name that is being
 * typed and may belong to nobody, while settings is asking about the session it is already
 * inside. Answering the first from preferences would offer the button for the wrong account.
 */
class GetBiometricUnlockState(
    private val repository: BiometricUnlockRepository,
    private val userPreferences: UserPreferences,
) : Usecase<GetBiometricUnlockState.Request, BiometricUnlockState> {

    sealed interface Request {
        /** The login screen: nobody is signed in, the name is whatever is in the field. */
        data class ForUsername(val username: String) : Request

        /** Settings: the account the screen belongs to. */
        data object ForSignedInUser : Request
    }

    override suspend fun invoke(param: Request): BiometricUnlockState {
        val username = when (param) {
            is Request.ForUsername -> param.username.trim()
            Request.ForSignedInUser -> (userPreferences.getUser() as? AppUser.LoggedIn)?.userName
        }
        // A blank name cannot be enrolled, and asking the platform anyway would light the login
        // button up on an empty field.
        if (username.isNullOrBlank()) return BiometricUnlockState.Unsupported
        return repository.biometricUnlockState(username)
    }
}
