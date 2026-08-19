package ai.passman.domain.settings.model

/**
 * The offline-recovery material a signed-in user explicitly requested from Settings.
 *
 * The recovery password is intentionally not persisted in preferences or attached to [AppUser].
 * It is shown only after the profile's normal keyring-backed login, then cleared by the screen.
 */
data class PortableVaultAccess(
    val profileDirectory: String,
    val pkcs12Path: String,
    val certificatePath: String,
    val vaultPath: String,
    val recoveryPassword: String,
    val recoveryFormat: PortableVaultRecoveryFormat,
)

enum class PortableVaultRecoveryFormat {
    /** The Base64URL recovery password used by the initial portable-vault release. */
    LegacyBase64Url,

    /** A standard English BIP39 phrase carrying 256 bits of entropy plus checksum. */
    Bip39English24,
}
