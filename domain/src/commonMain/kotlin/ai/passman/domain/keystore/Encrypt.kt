package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.repository.KeystoreRepository

class Encrypt(
    private val keystoreRepository: KeystoreRepository
) : Usecase<Encrypt.EncryptKeystoreData, Outcome<EncryptedData>> {

    sealed class EncryptKeystoreData {
        data class EncryptText(val keystorePath: String, val keystoreName: String, val keyAlias: String, val keyPassword: String, val salt: String, val plaintext: String): EncryptKeystoreData()
        data class EncryptFile(val keystorePath: String, val keystoreName: String, val keyAlias: String, val keyPassword: String, val salt: String, val filePath: String): EncryptKeystoreData()
    }

    override suspend fun invoke(param: EncryptKeystoreData): Outcome<EncryptedData> {
        return when (param) {
            is EncryptKeystoreData.EncryptText -> keystoreRepository.encryptText(param.keystorePath, param.keystoreName, param.keyAlias, param.keyPassword, param.salt, param.plaintext)
            is EncryptKeystoreData.EncryptFile -> keystoreRepository.encryptFile(param.keystorePath, param.keystoreName, param.keyAlias, param.keyPassword, param.salt, param.filePath)
        }
    }
}
