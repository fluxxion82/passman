package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.crypto.repository.CryptoPreferences
import com.russhwolf.settings.Settings
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

class LocalCryptoPreferences(
    encryptedFactory: EncryptionSettingsFactory,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : CryptoPreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)
    private val format = Json { explicitNulls = false; ignoreUnknownKeys = true }

    override fun getEncryptedKey(): String? = settings.getStringOrNull(CRYPTO_KEY)

    override fun setEncryptedKey(key: String?) {
        if (key == null) settings.remove(CRYPTO_KEY) else settings.putString(CRYPTO_KEY, key)
    }

    override suspend fun getEncryptedData(): EncryptedData? = withContext(coroutinesContextFacade.io) {
        val raw = settings.getStringOrNull(CIPHER_TEXT) ?: return@withContext null
        runCatching { format.decodeFromString<EncryptedData>(raw) }.getOrNull()
    }

    override suspend fun setEncryptedData(cipherData: EncryptedData) = withContext(coroutinesContextFacade.io) {
        settings.putString(CIPHER_TEXT, format.encodeToString(cipherData))
    }

    override fun clearEncryptedData() {
        settings.remove(CRYPTO_KEY)
        settings.remove(CIPHER_TEXT)
    }

    override fun clearKeys() = settings.clear()

    private companion object {
        const val PREFS_NAME = "user_vault"
        const val CRYPTO_KEY = "key"
        const val CIPHER_TEXT = "cipher"
    }
}
