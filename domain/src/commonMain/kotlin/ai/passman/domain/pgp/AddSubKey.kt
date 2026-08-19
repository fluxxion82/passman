package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class AddSubKey(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<AddSubKey.AddSubKeyRequest, Outcome<Unit>> {
    data class AddSubKeyRequest(
        val keyPair: PgpKeyPair,
        val password: String,
        val algorithm: PgpKeyAlgorithm,
        val length: Int,
        val expirationSeconds: Long,
    )
    override suspend fun invoke(param: AddSubKeyRequest): Outcome<Unit> {
        return pgpRepository.addSubKey(
            param.keyPair,
            param.password,
            param.algorithm,
            param.length,
            param.expirationSeconds,
        ).also {
            pgpEventPersistence.update(PgpEvent.KeyCreated)
        }
    }
}
