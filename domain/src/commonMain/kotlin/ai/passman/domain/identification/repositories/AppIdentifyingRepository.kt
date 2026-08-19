package ai.passman.domain.identification.repositories

interface AppIdentifyingRepository {
    suspend fun setIdentifier(token: String?)
    suspend fun getIdentifier(): String?
}
