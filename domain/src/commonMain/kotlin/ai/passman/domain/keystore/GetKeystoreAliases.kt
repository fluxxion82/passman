package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.repository.KeystoreRepository

class GetKeystoreAliases(
    private val keystoreRepository: KeystoreRepository,
) : Usecase<GetKeystoreAliases.AliasListRequest, Outcome<List<KeystoreKey>>> {
    data class AliasListRequest(val path: String, val name: String, val password: String)
    override suspend fun invoke(param: AliasListRequest): Outcome<List<KeystoreKey>> {
        return keystoreRepository.getAliases(param.path, param.name, param.password)
    }
}
