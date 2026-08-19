package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class VerifyClearSignature(
    private val pgpRepository: PgpRepository
) : Usecase<VerifyClearSignature.VerifyClearSignPgpData, Outcome<Unit>> {

    sealed interface VerifyClearSignPgpData
    data class VerifyClearSignPgpText(val signature: String, val publicKeyPath: String): VerifyClearSignPgpData
    data class VerifyClearSignPgpFile(val filePath: String, val publicKeyPath: String): VerifyClearSignPgpData

    override suspend fun invoke(param: VerifyClearSignPgpData): Outcome<Unit> {
        return when (param) {
            is VerifyClearSignPgpFile -> pgpRepository.verifyClearSignatureFile(param.filePath, param.publicKeyPath)
            is VerifyClearSignPgpText -> pgpRepository.verifyClearSignature(param.signature, param.publicKeyPath)
        }
    }
}
