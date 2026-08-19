package ai.passman.platform.crypto

interface SecureRandomService {
    fun nextBytes(size: Int): ByteArray
}
