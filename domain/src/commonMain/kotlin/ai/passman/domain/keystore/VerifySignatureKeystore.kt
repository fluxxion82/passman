package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.repository.KeystoreRepository

class VerifySignatureKeystore(
    private val keystoreRepository: KeystoreRepository,
): Usecase<VerifySignatureKeystore.VerifyRequest, Outcome<Boolean>> {

    sealed interface VerifyRequest
    data class VerifySignText(val keystorePath: String, val keystoreName: String, val keyAlias: String, val data: String, val signature: String): VerifyRequest
    data class VerifySignFile(val filePath: String, val keystorePath: String, val keystoreName: String, val signature: String, val keyAlias: String): VerifyRequest

    override suspend fun invoke(param: VerifyRequest): Outcome<Boolean> {
        return when (param) {
            is VerifySignFile -> keystoreRepository.verifySignatureFile(
                keystorePath = param.keystorePath,
                keystoreName = param.keystoreName,
                keyAlias = param.keyAlias,
                dataPath = param.filePath,
                signature = param.signature,
            )
            is VerifySignText -> keystoreRepository.verifySignature(
                keystorePath = param.keystorePath,
                keystoreName = param.keystoreName,
                keyAlias = param.keyAlias,
                data = param.data,
                signature = param.signature,
            )
        }
    }
}
