package ai.passman.domain.keystore.persistence

import ai.passman.domain.keystore.model.KeystoreEvent
import kotlinx.coroutines.flow.Flow

interface KeystoreEventPersistence {
    fun events(): Flow<KeystoreEvent>
    suspend fun update(event: KeystoreEvent)
}
