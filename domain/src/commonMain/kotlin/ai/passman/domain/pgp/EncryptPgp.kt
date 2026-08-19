package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class EncryptPgp(
    private val pgpRepository: PgpRepository,
) : Usecase<EncryptPgp.EncryptPgpData, Outcome<String>> {

    sealed class EncryptPgpData {
        data class EncryptPgpText(val plainText: String, val publicKeyPath: String, val armor: Boolean = true): EncryptPgpData()
        data class EncryptPgpFile(val filePath: String, val publicKeyPath: String, val armor: Boolean = true): EncryptPgpData()
    }

    override suspend fun invoke(param: EncryptPgpData): Outcome<String> {
        return when (param) {
            is EncryptPgpData.EncryptPgpText -> pgpRepository.encryptPgpMessage(param.plainText, param.publicKeyPath)
            is EncryptPgpData.EncryptPgpFile -> pgpRepository.encryptPgpFile(param.filePath, param.publicKeyPath)
        }
    }

}
