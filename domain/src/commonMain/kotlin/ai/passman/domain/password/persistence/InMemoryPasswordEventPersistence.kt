package ai.passman.domain.password.persistence

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.password.model.PasswordEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext

class InMemoryPasswordEventPersistence(
    private val contextFacade: CoroutinesContextFacade,
) : PasswordEventPersistence {
    private val events = MutableSharedFlow<PasswordEvent>(extraBufferCapacity = 64)

    override fun events(): Flow<PasswordEvent> = events

    override suspend fun update(event: PasswordEvent) = withContext(contextFacade.io) {
        events.emit(event)
    }
}
