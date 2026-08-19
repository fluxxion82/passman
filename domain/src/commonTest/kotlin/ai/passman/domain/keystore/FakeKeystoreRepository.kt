package ai.passman.domain.keystore

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.repository.KeystoreRepository

/**
 * Hand-written stand-in for [KeystoreRepository], in the [ai.passman.domain.pgp.FakePgpRepository]
 * style: only the methods a test configures get behaviour, everything else fails loudly.
 */
class FakeKeystoreRepository(
    private val allKeystores: () -> List<KeyStoreInfo> = { unsupported("getAllKeystores") },
    private val create: suspend (CreateKeyStore.CreateRequest) -> Outcome<KeyStoreInfo> =
        { unsupported("createKeyStore") },
    private val delete: (path: String, name: String, password: String) -> Boolean =
        { _, _, _ -> unsupported("deleteKeystore") },
) : KeystoreRepository {

    val createRequests = mutableListOf<CreateKeyStore.CreateRequest>()
    val deleteCalls = mutableListOf<Triple<String, String, String>>()

    override suspend fun createKeyStore(request: CreateKeyStore.CreateRequest): Outcome<KeyStoreInfo> {
        createRequests += request
        return create(request)
    }

    override suspend fun getAllKeystores(): List<KeyStoreInfo> = allKeystores()

    override suspend fun deleteKeystore(path: String, name: String, password: String): Boolean {
        deleteCalls += Triple(path, name, password)
        return delete(path, name, password)
    }

    override suspend fun importKeystoreFile(filepath: String): Outcome<Unit> = unsupported("importKeystoreFile")
    override suspend fun loadKeystore(path: String, name: String): KeyStoreInfo? = unsupported("loadKeystore")
    override suspend fun getAliases(path: String, keystoreName: String, password: String): Outcome<List<KeystoreKey>> =
        unsupported("getAliases")
    override suspend fun getKeystoreKey(keystorePath: String, keystoreName: String, alias: String): KeystoreKey =
        unsupported("getKeystoreKey")
    override suspend fun updateKeystore(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
        newKeyAlias: String?,
        newKeyPassword: String?,
        newKeyAlgo: KeystoreKeyAlgorithm?,
    ): Outcome<Unit> = unsupported("updateKeystore")
    override suspend fun deleteKeystoreKey(path: String, name: String, password: String, keyAlias: String): Boolean =
        unsupported("deleteKeystoreKey")
    override suspend fun encryptText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        plainData: String,
    ): Outcome<EncryptedData> = unsupported("encryptText")
    override suspend fun encryptFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        filePath: String,
    ): Outcome<EncryptedData> = unsupported("encryptFile")
    override suspend fun decryptText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        cipherData: String,
    ): Outcome<String> = unsupported("decryptText")
    override suspend fun decryptFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        filePath: String,
    ): Outcome<String> = unsupported("decryptFile")
    override suspend fun signText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        data: String,
        password: String,
    ): Outcome<String> = unsupported("signText")
    override suspend fun signFile(
        filePath: String,
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        password: String,
    ): Outcome<String> = unsupported("signFile")
    override suspend fun verifySignature(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        data: String,
        signature: String,
    ): Outcome<Boolean> = unsupported("verifySignature")
    override suspend fun verifySignatureFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        dataPath: String,
        signature: String,
    ): Outcome<Boolean> = unsupported("verifySignatureFile")
    override suspend fun getPublicKeyBytes(): ByteArray = unsupported("getPublicKeyBytes")
    override suspend fun transferKeystores(hostName: String): Outcome<Unit> = unsupported("transferKeystores")
    override suspend fun pushKeystores(hostName: String): Outcome<Unit> = unsupported("pushKeystores")
    override suspend fun pullKeystores(hostName: String): Outcome<Unit> = unsupported("pullKeystores")
    override fun clearKeyStore(): Unit = unsupported("clearKeyStore")

    companion object {
        private fun unsupported(name: String): Nothing =
            throw UnsupportedOperationException("FakeKeystoreRepository.$name was not configured for this test")
    }
}
