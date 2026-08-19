package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class DecryptPgp(
    private val pgpRepository: PgpRepository
) : Usecase<DecryptPgp.DecryptPgpData, Outcome<String>> {

    sealed class DecryptPgpData {
        data class DecryptPgpText(val encryptedText: String, val privateKeyPath: String, val password: String): DecryptPgpData()
        data class DecryptPgpFile(val encryptedFilePath: String, val privateKeyPath: String, val password: String): DecryptPgpData()
    }

    override suspend fun invoke(param: DecryptPgpData): Outcome<String> {
        return when (param) {
            is DecryptPgpData.DecryptPgpFile -> pgpRepository.decryptPgpFile(param.encryptedFilePath, param.privateKeyPath, param.password)
            is DecryptPgpData.DecryptPgpText -> pgpRepository.decryptPgpMessage(param.encryptedText, param.privateKeyPath, param.password)
        }
    }
}
