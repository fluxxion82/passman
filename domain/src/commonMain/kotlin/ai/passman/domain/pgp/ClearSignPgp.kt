package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class ClearSignPgp(
    private val pgpRepository: PgpRepository
) : Usecase<ClearSignPgp.ClearSignPgpData, Outcome<String>> {

    sealed interface ClearSignPgpData
    data class ClearSignPgpText(val text: String, val privateKeyPath: String, val password: String): ClearSignPgpData
    data class ClearSignPgpFile(val filePath: String, val privateKeyPath: String, val password: String): ClearSignPgpData

    override suspend fun invoke(param: ClearSignPgpData): Outcome<String> {
        return when (param) {
            is ClearSignPgpFile -> pgpRepository.clearSignFile(param.filePath, param.privateKeyPath, param.password)
            is ClearSignPgpText -> pgpRepository.clearSign(param.text, param.privateKeyPath, param.password)
        }
    }
}
