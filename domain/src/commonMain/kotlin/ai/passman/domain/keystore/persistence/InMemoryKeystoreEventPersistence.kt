package ai.passman.domain.keystore.persistence

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.keystore.model.KeystoreEvent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.withContext

class InMemoryKeystoreEventPersistence(
    private val contextFacade: CoroutinesContextFacade
) : KeystoreEventPersistence {

    private val events = MutableSharedFlow<KeystoreEvent>(extraBufferCapacity = 16)

    override fun events(): Flow<KeystoreEvent> = events

    override suspend fun update(event: KeystoreEvent) = withContext(contextFacade.default) {
        events.emit(event)
    }
}
