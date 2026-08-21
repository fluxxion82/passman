package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.repository.PreservedCopyRepository

/** Every version an inbound sync displaced on this device, newest first. */
class GetPreservedCopies(
    private val repository: PreservedCopyRepository,
) : Usecase<Unit, List<PreservedCopy>> {
    override suspend fun invoke(param: Unit): List<PreservedCopy> = repository.list()
}
