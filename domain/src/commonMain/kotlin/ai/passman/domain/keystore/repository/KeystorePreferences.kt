package ai.passman.domain.keystore.repository

import ai.passman.domain.keystore.model.KeyStoreInfo

interface KeystorePreferences {
    fun getSavedKeystoreList(): List<KeyStoreInfo>
    fun saveKeystore(keyStoreInfo: KeyStoreInfo)
}
