package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository

class AddPassword(
    private val passwordRepository: PasswordRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
) : Usecase<AddPassword.EntryData, Boolean> {

    data class EntryData(
        val entryName: String,
        val userName: String,
        val password: String,
        val website: String,
        val notes: String,
        val totpSeed: String = "",
        val customFields: List<CustomField> = emptyList(),
    )

    /** @return whether the entry was actually saved. No [PasswordEvent.Created] fires for a lost write. */
    override suspend fun invoke(param: EntryData): Boolean {
        val published = passwordRepository.addPasswordEntry(param)
        if (published) passwordEventPersistence.update(PasswordEvent.Created)
        return published
    }
}
