package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class DeleteKeystore(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
): Usecase<DeleteKeystore.DeleteKeystoreRequest, Boolean> {
    data class DeleteKeystoreRequest(
        val keystorePath: String,
        val keystoreName: String,
        val keystorePassword: String,
    )
    override suspend fun invoke(param: DeleteKeystoreRequest): Boolean {
        return keystoreRepository.deleteKeystore(
            path = param.keystorePath,
            name = param.keystoreName,
            password = param.keystorePassword,
        ).also {
            keystoreEventPersistence.update(
                KeystoreEvent.DeletedKeystore(param.keystorePath)
            )
        }
    }
}
