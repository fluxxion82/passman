package ai.passman.domain.pgp.persistence

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.pgp.model.PgpEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext

class InMemoryPgpEventPersistence(
    private val contextFacade: CoroutinesContextFacade
) : PgpEventPersistence {

    private val events = MutableSharedFlow<PgpEvent>(extraBufferCapacity = 64)

    override fun events(): Flow<PgpEvent> = events

    override suspend fun update(event: PgpEvent) = withContext(contextFacade.default) {
        events.emit(event)
    }
}
