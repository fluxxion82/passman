package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class ChangePgpKeyExpiry(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<ChangePgpKeyExpiry.ChangeKeyExpiryRequest, Unit> {
    data class ChangeKeyExpiryRequest(val keyPair: PgpKeyPair, val password: String, val expiry: Long)
    override suspend fun invoke(param: ChangeKeyExpiryRequest) {
        pgpRepository.changeKeyExpiry(param.keyPair, param.password, param.expiry)
    }
}
