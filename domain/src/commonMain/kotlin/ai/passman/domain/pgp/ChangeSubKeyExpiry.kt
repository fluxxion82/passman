package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class ChangeSubKeyExpiry(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<ChangeSubKeyExpiry.ChangeSubKeyExpiryRequest, Unit> {
    data class ChangeSubKeyExpiryRequest(val keyPair: PgpKeyPair, val password: String, val expiry: Long)
    override suspend fun invoke(param: ChangeSubKeyExpiryRequest) {
        pgpRepository.changeSubKeyExpiry(param.keyPair, param.password, param.expiry)
    }
}
