package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class ImportKeystore(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
): Usecase<String, Outcome<Unit>> {
    override suspend fun invoke(param: String): Outcome<Unit> {
        return keystoreRepository.importKeystoreFile(param).also {
            keystoreEventPersistence.update(KeystoreEvent.Created)
        }
    }
}
