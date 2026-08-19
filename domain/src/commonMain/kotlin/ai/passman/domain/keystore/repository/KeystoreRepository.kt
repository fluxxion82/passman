package ai.passman.domain.keystore.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.CreateKeyStore
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm

interface KeystoreRepository {
    suspend fun createKeyStore(request: CreateKeyStore.CreateRequest): Outcome<KeyStoreInfo>
    suspend fun importKeystoreFile(filepath: String): Outcome<Unit>
    suspend fun loadKeystore(path: String, name: String): KeyStoreInfo?
    suspend fun getAllKeystores(): List<KeyStoreInfo>
    suspend fun getAliases(path: String, keystoreName: String, password: String): Outcome<List<KeystoreKey>>
    suspend fun getKeystoreKey(keystorePath: String, keystoreName: String, alias: String): KeystoreKey
    suspend fun updateKeystore(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
        newKeyAlias: String?,
        newKeyPassword: String?,
        newKeyAlgo: KeystoreKeyAlgorithm?,
    ): Outcome<Unit>
    suspend fun deleteKeystore(path: String, name: String, password: String): Boolean
    suspend fun deleteKeystoreKey(path: String, name: String, password: String, keyAlias: String): Boolean

    suspend fun encryptText(
        keystorePath: String, keystoreName: String, keyAlias: String, keyPassword: String, cipherSalt: String, plainData: String
    ): Outcome<EncryptedData>
    suspend fun encryptFile(
        keystorePath: String, keystoreName: String, keyAlias: String, keyPassword: String, cipherSalt: String, filePath: String
    ): Outcome<EncryptedData>

    suspend fun decryptText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        cipherData: String,
    ): Outcome<String>
    suspend fun decryptFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        filePath: String,
    ): Outcome<String>

    suspend fun signText(keystorePath: String, keystoreName: String, keyAlias: String, data: String, password: String): Outcome<String>
    suspend fun signFile(filePath: String, keystorePath: String, keystoreName: String, keyAlias: String, password: String): Outcome<String>
    suspend fun verifySignature(keystorePath: String, keystoreName: String, keyAlias: String, data: String, signature: String): Outcome<Boolean>
    suspend fun verifySignatureFile(keystorePath: String, keystoreName: String, keyAlias: String, dataPath: String, signature: String): Outcome<Boolean>
    suspend fun getPublicKeyBytes(): ByteArray

    suspend fun transferKeystores(hostName: String): Outcome<Unit>
    suspend fun pushKeystores(hostName: String): Outcome<Unit>
    suspend fun pullKeystores(hostName: String): Outcome<Unit>

    fun clearKeyStore()
}
