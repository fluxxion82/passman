package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.repository.KeystoreRepository

class Decrypt(
    private val keystoreRepository: KeystoreRepository
) : Usecase<Decrypt.DecryptKeystoreData, Outcome<String>> {

    sealed class DecryptKeystoreData {
        data class DecryptText(
            val keystorePath: String,
            val keystoreName: String,
            val keyAlias: String,
            val keyPassword: String,
            val cipherSalt: String,
            val cipherText: String,
        ): DecryptKeystoreData()
        data class DecryptFile(
            val keystorePath: String,
            val keystoreName: String,
            val keyAlias: String,
            val keyPassword: String,
            val cipherSalt: String,
            val encryptedFilePath: String,
        ): DecryptKeystoreData()
    }

    override suspend fun invoke(param: DecryptKeystoreData): Outcome<String> {
        return when (param) {
            is DecryptKeystoreData.DecryptText -> keystoreRepository.decryptText(
                param.keystorePath, param.keystoreName, param.keyAlias, param.keyPassword, param.cipherSalt, param.cipherText
            )
            is DecryptKeystoreData.DecryptFile -> keystoreRepository.decryptFile(
                param.keystorePath, param.keystoreName, param.keyAlias, param.keyPassword, param.cipherSalt, param.encryptedFilePath
            )
        }
    }
}
