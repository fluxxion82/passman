package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class AddKeystoreKey(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
): Usecase<AddKeystoreKey.UpdateKeystoreRequest, Outcome<Unit>> {
    data class UpdateKeystoreRequest(
        val keystorePath: String,
        val keystorePassword: String,
        val keystoreName: String,
        val newKeyAlias: String?,
        val newKeyPassword: String?,
        val newKeyAlgo: KeystoreKeyAlgorithm?,
    )
    override suspend fun invoke(param: UpdateKeystoreRequest): Outcome<Unit> {
        return keystoreRepository.updateKeystore(
            keystorePath = param.keystorePath,
            keystoreName = param.keystoreName,
            keystorePassword = param.keystorePassword,
            newKeyAlias = param.newKeyAlias,
            newKeyPassword = param.newKeyPassword,
            newKeyAlgo = param.newKeyAlgo,
        ).also {
            keystoreEventPersistence.update(KeystoreEvent.Updated)
        }
    }
}
