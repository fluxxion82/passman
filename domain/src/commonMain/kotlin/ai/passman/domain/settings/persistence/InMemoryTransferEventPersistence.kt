package ai.passman.domain.settings.persistence

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.TransferEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext

class InMemoryTransferEventPersistence(
    private val contextFacade: CoroutinesContextFacade,
) : TransferEventPersistence {
    private val events = MutableSharedFlow<TransferEvent>(extraBufferCapacity = 6)

    override fun events(): Flow<TransferEvent> = events

    override suspend fun update(event: TransferEvent) = withContext(contextFacade.default) {
        events.emit(event)
    }
}
