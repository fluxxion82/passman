package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

class EncryptAndSignPgp(
    private val pgpRepository: PgpRepository
) : Usecase<EncryptAndSignPgp.EncryptAndSignPgpData, Outcome<String>> {

    sealed interface EncryptAndSignPgpData

    data class EncryptAndSignPgpText(
        val plainText: String,
        val publicKeyPath: String,
        val privateKeyPath: String,
        val password: String,
        val armor: Boolean
    ): EncryptAndSignPgpData

    data class EncryptAndSignPgpFile(
        val filePath: String,
        val publicKeyPath: String,
        val privateKeyPath: String,
        val password: String,
        val armor: Boolean
    ): EncryptAndSignPgpData

    override suspend fun invoke(param: EncryptAndSignPgpData): Outcome<String> {
        return when (param) {
            is EncryptAndSignPgpText -> pgpRepository.signAndEncrypt(
                plainText = param.plainText,
                publicKeyPath = param.publicKeyPath,
                privateKeyPath = param.privateKeyPath,
                keyPassword = param.password,
            )
            is EncryptAndSignPgpFile -> pgpRepository.signAndEncryptFile(
                plainFilePath = param.filePath,
                publicKeyPath = param.publicKeyPath,
                privateKeyPath = param.privateKeyPath,
                keyPassword = param.password,
            )
        }
    }
}
