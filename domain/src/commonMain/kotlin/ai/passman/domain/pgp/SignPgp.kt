package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class SignPgp(
    private val pgpRepository: PgpRepository
) : Usecase<SignPgp.SignPgpData, Outcome<String>> {

    data class SignPgpData(
        val text: String,
        val privateKeyPath: String,
        val password: String,
        val armor: Boolean,
        val digestName: String = "SHA256"
    )

    override suspend fun invoke(param: SignPgpData): Outcome<String> =
        pgpRepository.sign(param.text, param.privateKeyPath, param.password, param.armor, param.digestName)
}
