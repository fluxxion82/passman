package ai.passman.domain.keystore.repository

import ai.passman.domain.keystore.model.KeyStoreInfo

interface KeystorePreferences {
    fun getSavedKeystoreList(): List<KeyStoreInfo>
    fun saveKeystore(keyStoreInfo: KeyStoreInfo)

    /**
     * Whether [ai.passman.domain.keystore.EnsureDefaultKeystore] already ran for [userName] on
     * this device. Set after the starter keystore is created — and also when the guard finds the
     * account already has keystores or the starter vault entry (including ones that arrived by
     * sync), so that a user who deletes the starter keystore never has it silently resurrected.
     * Deliberately a device-local preference, never a file in the synced keystore directory.
     */
    fun isDefaultKeystoreCreated(userName: String): Boolean
    fun setDefaultKeystoreCreated(userName: String)
}
