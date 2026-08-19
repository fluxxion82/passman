package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.repository.KeystoreRepository

class SignWithKey(
    private val keystoreRepository: KeystoreRepository,
): Usecase<SignWithKey.SignRequest, Outcome<String>> {

    sealed interface SignRequest
    data class SignText(val dataToSign: String, val keystorePath: String, val keystoreName: String, val keyAlias: String, val keyPassword: String): SignRequest
    data class SignFile(val filePath: String, val keystorePath: String, val keystoreName: String, val keyAlias: String, val keyPassword: String): SignRequest

    override suspend fun invoke(param: SignRequest): Outcome<String> {
        return when (param) {
            is SignFile -> keystoreRepository.signFile(
                filePath = param.filePath,
                keystorePath = param.keystorePath,
                keystoreName = param.keystoreName,
                keyAlias = param.keyAlias,
                password = param.keyPassword,
            )
            is SignText -> keystoreRepository.signText(
                keystorePath = param.keystorePath,
                keystoreName = param.keystoreName,
                keyAlias = param.keyAlias,
                data = param.dataToSign,
                password = param.keyPassword,
            )
        }
    }
}
