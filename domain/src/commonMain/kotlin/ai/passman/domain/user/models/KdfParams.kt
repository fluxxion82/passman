package ai.passman.domain.user.models

import kotlinx.serialization.Serializable

/**
 * Self-describing parameters for the login-password key-derivation function. Persisted alongside the
 * stored credential so a hash can always be verified with the exact params it was produced under, and
 * upgraded transparently: on a successful login whose stored params aren't [ARGON2ID_DEFAULT], the
 * credential is re-derived and re-saved with the current target (rehash-on-login). A missing/`null`
 * params on an old credential means [LEGACY_PBKDF2] — the format used before this field existed.
 */
@Serializable
data class KdfParams(
    val algorithm: String,
    val keyLengthBytes: Int,
    val iterations: Int = 0,   // PBKDF2 iteration count, or Argon2 time cost (t)
    val memoryKib: Int = 0,    // Argon2 only (m)
    val parallelism: Int = 0,  // Argon2 only (p)
) {
    companion object {
        const val PBKDF2_SHA256 = "pbkdf2-sha256"
        const val ARGON2ID = "argon2id"

        /** What credentials written before versioned KDF params used: PBKDF2-HMAC-SHA256, 130k, 2048-bit output. */
        val LEGACY_PBKDF2 = KdfParams(
            algorithm = PBKDF2_SHA256,
            keyLengthBytes = 256,
            iterations = 130_000,
        )

        /** Current target for new + rehashed credentials: Argon2id, 64 MiB, t=3, p=1, 32-byte output. */
        val ARGON2ID_DEFAULT = KdfParams(
            algorithm = ARGON2ID,
            keyLengthBytes = 32,
            iterations = 3,
            memoryKib = 64 * 1024,
            parallelism = 1,
        )
    }
}
