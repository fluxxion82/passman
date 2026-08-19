package ai.passman.platform.crypto

import java.security.SecureRandom

class JvmSecureRandomService : SecureRandomService {
    private val random = SecureRandom()
    override fun nextBytes(size: Int): ByteArray {
        val out = ByteArray(size)
        random.nextBytes(out)
        return out
    }
}
