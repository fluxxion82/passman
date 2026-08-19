package ai.passman.platform.crypto

/**
 * SHA-256, behind the same platform seam [SecureRandomService] already uses.
 *
 * This module's `commonMain` compiles for iOS as well as JVM and Android, and the Kotlin stdlib has
 * no digest, so the one caller that needs one — the legacy password-entry uuid derivation in
 * [ai.passman.platform.repository.PasswordEntryIdentity] — takes it as a dependency instead of
 * reaching for `java.security.MessageDigest` from code iOS also compiles.
 */
fun interface Sha256Service {
    fun sha256(input: ByteArray): ByteArray
}
