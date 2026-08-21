package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.repository.PreservedCopyRepository

/**
 * Makes a displaced version live again, preserving whatever it replaces.
 *
 * False means the copy is gone or its recorded path does not resolve inside its artifact directory.
 */
class RestorePreservedCopy(
    private val repository: PreservedCopyRepository,
) : Usecase<PreservedCopy, Boolean> {
    override suspend fun invoke(param: PreservedCopy): Boolean = repository.restore(param)
}
