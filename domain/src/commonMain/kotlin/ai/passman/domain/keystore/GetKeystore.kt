package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.keystore.repository.KeystoreRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart

class GetKeystore(
    private val keystoreRepository: KeystoreRepository,
    private val keystoreEventPersistence: KeystoreEventPersistence,
) : Usecase<GetKeystore.GetKeystoreRequest, Flow<KeyStoreInfo>> {
    data class GetKeystoreRequest(val path: String, val name: String)
    override suspend fun invoke(param: GetKeystoreRequest): Flow<KeyStoreInfo> = channelFlow {
        keystoreEventPersistence.events()
            .onStart {
                keystoreRepository.loadKeystore(param.path, param.name)?.let {
                    send(it)
                }
            }
            .map { keystoreRepository.loadKeystore(param.path, param.name) }
            .collect { keystore ->
                keystore?.let {
                    send(it)
                }
            }
    }
}
