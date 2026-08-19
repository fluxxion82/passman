package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.UserId
import ai.passman.domain.pgp.model.UserIdAction
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class UpdateUserId(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<UpdateUserId.UpdateUserIdRequest, Outcome<Unit>> {
    data class UpdateUserIdRequest(
        val keyPair: PgpKeyPair,
        val password: String,
        val userId: UserId,
        val userIdAction: UserIdAction,
    )
    override suspend fun invoke(param: UpdateUserIdRequest): Outcome<Unit> {
        return pgpRepository.modifyUserId(param.keyPair, param.password, param.userId, param.userIdAction).also {
            pgpEventPersistence.update(PgpEvent.UserIdModification)
        }
    }
}
