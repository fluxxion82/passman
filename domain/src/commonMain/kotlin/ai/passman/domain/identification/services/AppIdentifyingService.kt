package ai.passman.domain.identification.services

interface AppIdentifyingService {
    suspend fun clearIdentifier()
    suspend fun getIdentifier(): String
}
