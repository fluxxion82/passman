package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.repository.PreservedCopyRepository

/**
 * Permanently deletes a displaced version.
 *
 * Deliberately available, and deliberately final. These are private key material that no other
 * screen can reach, so without this they would be undeletable — a superseded ring under a passphrase
 * the user rotated *because it leaked* would guard live private bytes on disk forever. Callers must
 * confirm first; nothing below this recovers it.
 */
class DeletePreservedCopy(
    private val repository: PreservedCopyRepository,
) : Usecase<PreservedCopy, Boolean> {
    override suspend fun invoke(param: PreservedCopy): Boolean = repository.delete(param)
}
