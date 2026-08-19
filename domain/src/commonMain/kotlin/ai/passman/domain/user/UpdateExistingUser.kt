package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences

class UpdateExistingUser(
    private val preferences: UserPreferences,
    private val userEventPersistence: UserEventPersistence
) : Usecase<AppUser, Unit> {

    override suspend fun invoke(param: AppUser) {
        preferences.upsert(param)
        userEventPersistence.update(UserEvent.LoginChanged(param))
    }
}
