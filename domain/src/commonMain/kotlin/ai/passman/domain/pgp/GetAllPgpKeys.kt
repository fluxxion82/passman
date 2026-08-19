package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart

class GetAllPgpKeys(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<Unit, Flow<List<PgpKeyPair>>> {
    override suspend fun invoke(param: Unit): Flow<List<PgpKeyPair>> = channelFlow {
        pgpEventPersistence.events()
            .onStart {
                send(pgpRepository.getKeys())
            }.map {
                pgpRepository.getKeys()
            }.collect {
                send(it)
            }
    }
}
