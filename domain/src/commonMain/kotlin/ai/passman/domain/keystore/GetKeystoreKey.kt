package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.repository.KeystoreRepository

class GetKeystoreKey(
    private val keystoreRepository: KeystoreRepository,
): Usecase<GetKeystoreKey.KeystoreKeyRequest, KeystoreKey> {
    data class KeystoreKeyRequest(val keystorePath: String, val keystoreName: String, val keyAlias: String)
    override suspend fun invoke(param: KeystoreKeyRequest): KeystoreKey {
        return keystoreRepository.getKeystoreKey(param.keystorePath, param.keystoreName, param.keyAlias)
    }
}
