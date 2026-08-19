package ai.passman.domain.identification

import ai.passman.domain.base.Usecase
import ai.passman.domain.identification.repositories.AppIdentifyingRepository

class UpdateIdentifier(
    private val repository: AppIdentifyingRepository
) : Usecase<String, Unit> {

    override suspend fun invoke(param: String) {
        repository.setIdentifier(param)
    }
}
