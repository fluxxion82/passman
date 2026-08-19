package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.onStart

class GetAppUser(
    private val userPreferences: UserPreferences,
    private val userEvents: UserEventPersistence
) : Usecase<Unit, Flow<AppUser>> {

    override suspend fun invoke(param: Unit): Flow<AppUser> =
        userEvents.events()
            .mapNotNull { (it as? UserEvent.LoginChanged)?.user }
            .onStart {
                emit(userPreferences.getUser())
            }
}
