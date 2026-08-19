package ai.passman.domain.user.persistences

import ai.passman.domain.user.models.UserEvent
import kotlinx.coroutines.flow.Flow

interface UserEventPersistence {
    fun events(): Flow<UserEvent>
    suspend fun update(event: UserEvent)
}
