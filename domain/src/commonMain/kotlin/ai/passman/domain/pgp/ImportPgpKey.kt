package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

class ImportPgpKey(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
): Usecase<String, Outcome<Unit>> {
    override suspend fun invoke(param: String): Outcome<Unit> {
        return pgpRepository.importPgpFile(param).also {
            pgpEventPersistence.update(PgpEvent.KeyCreated)
        }
    }
}
