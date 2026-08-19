package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository

class ChangeUserPassword(
    private val userRepository: UserRepository,
    private val userPreferences: UserPreferences,
) : Usecase<ChangeUserPassword.ChangePasswordRequest, Outcome<Unit>> {
    data class ChangePasswordRequest(val oldPassword: String, val newPassword: String)

    override suspend fun invoke(param: ChangePasswordRequest): Outcome<Unit> {
        when (val outcome = userRepository.changeUserPassword(param.oldPassword, param.newPassword)) {
            is Outcome.Success -> {
                userPreferences.upsert(outcome.value)
                return Outcome.Success(Unit)
            }
            is Outcome.Error -> return outcome
        }
    }
}
