package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class DecryptAndVerify(
    private val pgpRepository: PgpRepository
) : Usecase<DecryptAndVerify.DecryptAndVerifyRequest, Outcome<String>> {

    sealed interface DecryptAndVerifyRequest
    data class DecryptAndVerifyText(val encryptedText: String, val privateKeyPath: String, val publicKeyPath: String, val password: String): DecryptAndVerifyRequest
    data class DecryptAndVerifyFile(val encryptedFilePath: String, val privateKeyPath: String, val publicKeyPath: String, val password: String): DecryptAndVerifyRequest

    override suspend fun invoke(param: DecryptAndVerifyRequest): Outcome<String> {
        return when (param) {
            is DecryptAndVerifyFile -> pgpRepository.verifyAndDecryptFile(
                encryptedFilePath = param.encryptedFilePath,
                privateKeyPath = param.privateKeyPath,
                publicKeyPath = param.publicKeyPath,
                keyPassword = param.password,
            )
            is DecryptAndVerifyText -> pgpRepository.verifyAndDecrypt(
                encryptedText = param.encryptedText,
                privateKeyPath = param.privateKeyPath,
                publicKeyPath = param.publicKeyPath,
                keyPassword = param.password,
            )
        }
    }
}
