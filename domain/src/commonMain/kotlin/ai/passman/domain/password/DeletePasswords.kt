package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository

/** @param param the entries' [PasswordEntry.uuid]s. Display ordinals do not identify rows. */
class DeletePasswords(
    private val passwordRepository: PasswordRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
) : Usecase<Collection<String>, Int> {
    override suspend fun invoke(param: Collection<String>): Int {
        if (param.isEmpty()) return 0
        val deleted = passwordRepository.deletePasswordEntries(param)
        // A batch that removed nothing left the vault byte-identical; an event would claim an update
        // that never happened. The count already tells the caller the honest story either way.
        if (deleted > 0) passwordEventPersistence.update(PasswordEvent.Updated)
        return deleted
    }
}
