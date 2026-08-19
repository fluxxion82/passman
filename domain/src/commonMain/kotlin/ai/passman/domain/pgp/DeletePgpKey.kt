package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class DeletePgpKey(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<Long, Outcome<Unit>> {
    override suspend fun invoke(param: Long): Outcome<Unit> {
        return pgpRepository.deletePgpKey(param).also { outcome ->
            // Notify observers so the reactive GetAllPgpKeys re-fetches and the list refreshes
            // immediately, instead of only after the screen is recreated on navigation.
            if (outcome.isSuccessful()) {
                pgpEventPersistence.update(PgpEvent.KeyModified)
            }
        }
    }
}
