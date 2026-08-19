package ai.passman.platform.service

interface PgpKeyRingService {
    suspend fun createKeyRings(userId: String, password: String, keyDirectory: String): Result<Unit>
}
