package ai.passman.domain.app.persistence

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow

class InMemoryForegroundEventPersistence() : ForegroundEventPersistence {
    private val foregroundEvent = MutableSharedFlow<Boolean>()

    override fun getForegroundEvent(): Flow<Boolean> = foregroundEvent

    override suspend fun update(foreground: Boolean) {
        foregroundEvent.emit(foreground)
    }
}
