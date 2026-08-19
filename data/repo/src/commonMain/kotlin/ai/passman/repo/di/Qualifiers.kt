package ai.passman.repo.di

const val PUBLIC_ENCRYPTION_KEY_HANDLE = "encryptionKeyHandle"
const val PRIVATE_DECRYPTION_KEY_HANDLE = "decryptionKeyHandle"

/**
 * Session-scoped holder for the unwrapped device master key (`ai.passman.crypto.vault.VaultSession`).
 *
 * Lives beside the RSA key handles because it has the same lifetime and the same scope, and in
 * `commonMain` because `LocalUserRepository` — the only writer — is a `commonMain` file that compiles
 * for iOS.
 */
const val VAULT_SESSION_HANDLE = "vaultSessionHandle"
