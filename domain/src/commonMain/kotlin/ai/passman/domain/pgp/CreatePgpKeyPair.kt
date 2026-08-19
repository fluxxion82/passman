package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class CreatePgpKeyPair(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<CreatePgpKeyPair.CreatePgpKey, Outcome<String>> {
    data class CreatePgpKey(
        val name: String,
        val email: String,
        val algorithm: PgpKeyAlgorithm,
        val length: Int,
        val expirationSeconds: Long,
        val password: String,
    )
    override suspend fun invoke(param: CreatePgpKey): Outcome<String> {
        return pgpRepository.createPgpKey(
            param.name,
            param.email,
            param.password,
            param.algorithm,
            param.length,
            param.expirationSeconds,
        ).also {
            pgpEventPersistence.update(PgpEvent.KeyCreated)
        }
    }
}
