package ai.passman.platform.crypto

import java.security.MessageDigest

class JvmSha256Service : Sha256Service {
    // A fresh MessageDigest per call: it is stateful, and this service is registered as a singleton
    // that two vault reads on different threads can reach at the same time.
    override fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)
}
