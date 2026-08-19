package ai.passman.platform.vault

import ai.passman.crypto.vault.VaultSessionKey

/** Standard, profile-portable primary password-vault representation. */
interface PortableVaultFormat {
    fun seal(username: String, plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray
    fun open(username: String, ciphertext: ByteArray, sessionKey: VaultSessionKey): ByteArray
    fun isPortable(ciphertext: ByteArray): Boolean
}
