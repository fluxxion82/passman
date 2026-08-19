package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart

class GetAllKeystores(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
) : Usecase<Unit, Flow<List<KeyStoreInfo>>> {
    override suspend fun invoke(param: Unit): Flow<List<KeyStoreInfo>> = channelFlow {
        keystoreEventPersistence.events()
            .onStart {
                send(keystoreRepository.getAllKeystores())
            }.map {
                keystoreRepository.getAllKeystores()
            }.collect {
                send(it)
            }
    }
}
