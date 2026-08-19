package ai.passman.domain.keystore

import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.repository.KeystorePreferences

/** In-memory [KeystorePreferences]: the flag works; the saved-list methods fail loudly. */
class FakeKeystorePreferences : KeystorePreferences {
    private val defaultCreated = mutableSetOf<String>()

    fun isFlagSet(userName: String): Boolean = userName in defaultCreated
    fun presetFlag(userName: String) {
        defaultCreated += userName
    }

    override fun isDefaultKeystoreCreated(userName: String): Boolean = userName in defaultCreated

    override fun setDefaultKeystoreCreated(userName: String) {
        defaultCreated += userName
    }

    override fun getSavedKeystoreList(): List<KeyStoreInfo> =
        throw UnsupportedOperationException("FakeKeystorePreferences.getSavedKeystoreList was not configured")

    override fun saveKeystore(keyStoreInfo: KeyStoreInfo): Unit =
        throw UnsupportedOperationException("FakeKeystorePreferences.saveKeystore was not configured")
}
