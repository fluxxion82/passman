package ai.passman.domain.pgp.persistence

import ai.passman.domain.pgp.model.PgpEvent
import kotlinx.coroutines.flow.Flow

interface PgpEventPersistence {
    fun events(): Flow<PgpEvent>
    suspend fun update(event: PgpEvent)
}
