package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository

class UpdatePassword(
    private val passwordRepository: PasswordRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
) : Usecase<PasswordEntry, Boolean> {

    /** @return whether the edit was actually saved. No [PasswordEvent.Updated] fires for a lost write. */
    override suspend fun invoke(param: PasswordEntry): Boolean {
        val published = passwordRepository.updatePasswordEntry(param)
        if (published) passwordEventPersistence.update(PasswordEvent.Updated)
        return published
    }
}
