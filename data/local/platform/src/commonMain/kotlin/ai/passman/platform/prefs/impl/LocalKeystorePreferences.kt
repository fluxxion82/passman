package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.repository.KeystorePreferences
import com.russhwolf.settings.Settings
import kotlinx.serialization.json.Json

class LocalKeystorePreferences(
    encryptedFactory: EncryptionSettingsFactory,
) : KeystorePreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)
    private val format = Json { ignoreUnknownKeys = true }

    override fun getSavedKeystoreList(): List<KeyStoreInfo> {
        val raw = settings.getStringOrNull(KEYSTORE_LIST) ?: return emptyList()
        return runCatching { format.decodeFromString<List<KeyStoreInfo>>(raw) }.getOrElse { emptyList() }
    }

    override fun saveKeystore(keyStoreInfo: KeyStoreInfo) {
        val current = getSavedKeystoreList().toMutableList()
        current.add(keyStoreInfo)
        settings.putString(KEYSTORE_LIST, format.encodeToString(current))
    }

    // Keyed per account (the store is shared by every account on the device) and deliberately
    // never cleared on keystore deletion — the flag is what makes deleting the starter keystore
    // final. Same pattern as LocalPgpPreferences' developer-key flag.
    override fun isDefaultKeystoreCreated(userName: String): Boolean =
        settings.getBoolean(defaultKeystoreCreatedKey(userName), false)

    override fun setDefaultKeystoreCreated(userName: String) {
        settings.putBoolean(defaultKeystoreCreatedKey(userName), true)
    }

    private fun defaultKeystoreCreatedKey(userName: String) = "$DEFAULT_KEYSTORE_CREATED_PREFIX$userName"

    private companion object {
        const val PREFS_NAME = "keystore"
        const val KEYSTORE_LIST = "keystoreList"
        const val DEFAULT_KEYSTORE_CREATED_PREFIX = "default_keystore_created_"
    }
}
