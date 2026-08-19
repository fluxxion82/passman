package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences

class GetUserState(
    private val userPreferences: UserPreferences,
    private val userEvents: UserEventPersistence
) : Usecase<Unit, UserState> {

    override suspend fun invoke(param: Unit): UserState {
        val user = userPreferences.getUser()
        userEvents.update(UserEvent.LoginChanged(user)) // ?
        return when (user) {
            AppUser.Anonymous -> UserState.Anonymous
            is AppUser.LoggedIn, is AppUser.AccountCreated -> {
                when (val cachedState = userPreferences.getUserState()) {
                    null -> UserState.LoggedIn
                    else -> cachedState
                }
            }
        }
    }
}
