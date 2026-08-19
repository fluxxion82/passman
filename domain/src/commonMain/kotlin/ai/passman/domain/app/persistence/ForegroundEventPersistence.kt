package ai.passman.domain.app.persistence

import kotlinx.coroutines.flow.Flow

interface ForegroundEventPersistence {
    fun getForegroundEvent(): Flow<Boolean>
    suspend fun update(foreground: Boolean)
}
