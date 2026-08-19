package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository

/** @param param the entry's [PasswordEntry.uuid]. The display ordinal does not identify a row. */
class DeletePassword(
    private val passwordRepository: PasswordRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
) : Usecase<String, Boolean> {
    /** @return whether a row was removed. No [PasswordEvent.Deleted] fires for a lost write or an absent target. */
    override suspend fun invoke(param: String): Boolean {
        val published = passwordRepository.deletePasswordEntry(param)
        if (published) passwordEventPersistence.update(PasswordEvent.Deleted(param))
        return published
    }
}
