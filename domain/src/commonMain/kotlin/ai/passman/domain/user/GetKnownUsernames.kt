package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.repository.UserPreferences

class GetKnownUsernames(
    private val userPreferences: UserPreferences,
) : Usecase<Unit, List<String>> {

    override suspend fun invoke(param: Unit): List<String> = userPreferences.getKnownUsernames()
}
