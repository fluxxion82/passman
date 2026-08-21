package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.repository.PreservedCopyRepository

/** Path of a displaced version, for handing to the platform share/save flow. Null if it is gone. */
class GetPreservedCopyPath(
    private val repository: PreservedCopyRepository,
) : Usecase<PreservedCopy, String?> {
    override suspend fun invoke(param: PreservedCopy): String? = repository.pathOf(param)
}
