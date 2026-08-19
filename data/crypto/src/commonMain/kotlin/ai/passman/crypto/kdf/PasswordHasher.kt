package ai.passman.crypto.kdf

import ai.passman.domain.user.models.KdfParams

interface PasswordHasher {
    /** Derive a key from [password] and [salt] using the algorithm + cost in [params]. */
    fun derive(password: String, salt: ByteArray, params: KdfParams): ByteArray
}
