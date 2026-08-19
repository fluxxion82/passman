package ai.passman.domain.crypto.repository

import ai.passman.domain.crypto.model.EncryptedData

interface CryptoPreferences {
    fun getEncryptedKey(): String?
    fun setEncryptedKey(key: String?)
    suspend fun getEncryptedData(): EncryptedData?
    suspend fun setEncryptedData(cipherData: EncryptedData)
    fun clearEncryptedData()
    fun clearKeys()
}
