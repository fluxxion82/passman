package ai.passman.domain.password.persistence

import ai.passman.domain.password.model.PasswordEvent
import kotlinx.coroutines.flow.Flow

interface PasswordEventPersistence {
    fun events(): Flow<PasswordEvent>
    suspend fun update(event: PasswordEvent)
}
