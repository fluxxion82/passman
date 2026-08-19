package ai.passman.crypto

/**
 * Opaque platform-agnostic handle to a cryptographic key.
 *
 * On JVM/Android this wraps `java.security.Key` (BouncyCastle public/private/secret keys all
 * implement that interface). On iOS it currently holds nothing useful — the iOS keystore/PGP
 * backends are stubbed until ObjectivePGP cinterop (PGP) and Apple Keychain Services
 * (Keystore) wiring lands. See data/pgp and data/keystore iosMain.
 */
expect class CryptoKey {
    val encoded: ByteArray
}
