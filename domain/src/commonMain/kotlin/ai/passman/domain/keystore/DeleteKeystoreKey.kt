package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class DeleteKeystoreKey(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
): Usecase<DeleteKeystoreKey.DeleteKeystoreKeyRequest, Boolean> {
    data class DeleteKeystoreKeyRequest(
        val keystorePath: String,
        val keystoreName: String,
        val keystorePassword: String,
        val keystoreKeyAlias: String,
    )
    override suspend fun invoke(param: DeleteKeystoreKeyRequest): Boolean {
        return keystoreRepository.deleteKeystoreKey(
            path = param.keystorePath,
            name = param.keystoreName,
            password = param.keystorePassword,
            keyAlias = param.keystoreKeyAlias,
        ).also {
            keystoreEventPersistence.update(
                KeystoreEvent.DeletedKeystoreKey(param.keystorePath, param.keystoreKeyAlias)
            )
        }
    }
}
