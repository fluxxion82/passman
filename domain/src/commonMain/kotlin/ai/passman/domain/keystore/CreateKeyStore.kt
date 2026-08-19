package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class CreateKeyStore(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
) : Usecase<CreateKeyStore.CreateRequest, Outcome<KeyStoreInfo>> {

    data class CreateRequest(
        val keystoreName: String,
        val keystorePassword: String,
        val keyAlgorithm: KeystoreKeyAlgorithm,
        val keyAlias: String,
        val aliasPassword: String,
        val keystoreType: KeyStoreType,
    )
    override suspend fun invoke(param: CreateRequest): Outcome<KeyStoreInfo> {
        val outcome = keystoreRepository.createKeyStore(param)
        // Success only: a failed creation leaves nothing on disk (the repository even removes the
        // store when its key generation fails), so an event would just trigger a pointless list
        // reload announcing a keystore that does not exist.
        if (outcome is Outcome.Success) {
            keystoreEventPersistence.update(KeystoreEvent.Created)
        }
        return outcome
    }
}
