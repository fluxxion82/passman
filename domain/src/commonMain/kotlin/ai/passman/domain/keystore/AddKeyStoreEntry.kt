package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository

class AddKeyStoreEntry(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
) : Usecase<AddKeyStoreEntry.Info, Unit> {

    data class Info(
        val keyStore: KeyStoreInfo,
        val alias: String,
        val password: String
    )

    override suspend fun invoke(param: Info) {
        // keystoreRepository
    }
}
