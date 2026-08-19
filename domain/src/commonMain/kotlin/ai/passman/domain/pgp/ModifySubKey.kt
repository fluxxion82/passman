package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class ModifySubKey(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<ModifySubKey.ModifySubkeyRequest, Outcome<Unit>> {
    data class ModifySubkeyRequest(
        val keyPair: PgpKeyPair,
        val password: String,
        val subKeyId: String,
        val action: SubKeyAction,
    )
    override suspend fun invoke(param: ModifySubkeyRequest): Outcome<Unit> {
        return pgpRepository.modifySubKey(
            param.keyPair,
            param.password,
            param.subKeyId,
            param.action,
        ).apply {
            pgpEventPersistence.update(PgpEvent.KeyModified)
        }
    }
}
