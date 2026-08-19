package ai.passman.domain.connectivity.persistence

import ai.passman.domain.connectivity.model.ConnectionState
import kotlinx.coroutines.flow.Flow

interface ConnectionMonitor {
    suspend fun getConnectionState(): Flow<ConnectionState>
}
