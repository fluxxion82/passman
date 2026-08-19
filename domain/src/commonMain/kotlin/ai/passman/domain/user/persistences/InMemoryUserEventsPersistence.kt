package ai.passman.domain.user.persistences

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.user.models.UserEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext

class InMemoryUserEventsPersistence(
    private val contextFacade: CoroutinesContextFacade
) : UserEventPersistence {

    private val eventFlow = MutableSharedFlow<UserEvent>(extraBufferCapacity = 64)

    override fun events(): Flow<UserEvent> = eventFlow

    override suspend fun update(event: UserEvent) = withContext(contextFacade.default) {
        eventFlow.emit(event)
    }
}
