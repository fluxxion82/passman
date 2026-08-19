package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.repository.PasswordRepository

/**
 * @param param the entry's [PasswordEntry.uuid]. The display ordinal does not identify a row.
 *
 * `find` rather than a filter, and that is the contract: an identity derived for an entry that
 * predates the uuid field is unique only up to name *and* username, so two rows can answer to one
 * uuid. This resolves to the first of them, which is the same row `deletePasswordEntry` and
 * `updatePasswordEntry` act on, so opening one and editing it stays self-consistent.
 */
class GetPassword(
    private val passwordRepository: PasswordRepository,
) : Usecase<String, PasswordEntry?> {

    override suspend fun invoke(param: String): PasswordEntry? {
        return passwordRepository.getPasswordEntries().find { it.uuid == param }
    }
}
