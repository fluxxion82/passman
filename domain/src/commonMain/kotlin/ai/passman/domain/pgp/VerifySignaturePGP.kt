package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class VerifySignaturePGP(
    private val pgpRepository: PgpRepository
) : Usecase<VerifySignaturePGP.VerifySignPgpData, Outcome<Unit>> {

    data class VerifySignPgpData(val signature: String, val publicKeyPath: String)

    override suspend fun invoke(param: VerifySignPgpData): Outcome<Unit> =
        pgpRepository.verifySignature(param.publicKeyPath, param.signature)
}
