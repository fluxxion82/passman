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

    private companion object {
        const val PREFS_NAME = "keystore"
        const val KEYSTORE_LIST = "keystoreList"
    }
}
