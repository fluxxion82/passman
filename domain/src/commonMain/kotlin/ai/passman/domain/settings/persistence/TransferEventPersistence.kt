package ai.passman.domain.settings.persistence

import ai.passman.domain.settings.model.TransferEvent
import kotlinx.coroutines.flow.Flow

interface TransferEventPersistence {
    fun events(): Flow<TransferEvent>
    suspend fun update(event: TransferEvent)
}
