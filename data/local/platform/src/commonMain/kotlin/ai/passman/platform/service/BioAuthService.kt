package ai.passman.platform.service

interface BioAuthService {
    sealed class Result {
        data object Success : Result()
        data object Failed : Result()
        data object Unavailable : Result()
    }

    suspend fun authenticate(hardwareKeySeed: ByteArray? = null): Result
}
