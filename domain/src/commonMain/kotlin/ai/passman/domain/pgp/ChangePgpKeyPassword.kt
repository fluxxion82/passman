package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class ChangePgpKeyPassword(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<ChangePgpKeyPassword.ChangePgpKeyPasswordRequest, Outcome<Unit>> {
    data class ChangePgpKeyPasswordRequest(
        val oldPassword: String,
        val newPassword: String,
        val keyPair: PgpKeyPair,
    )
    override suspend fun invoke(param: ChangePgpKeyPasswordRequest): Outcome<Unit> {
        return pgpRepository.changeKeyPassword(param.keyPair, param.oldPassword, param.newPassword).also {
            pgpEventPersistence.update(PgpEvent.KeyModified)
        }
    }
}
