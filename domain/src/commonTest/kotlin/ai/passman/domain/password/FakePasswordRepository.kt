package ai.passman.domain.password

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.repository.PasswordRepository

/**
 * Hand-written stand-in for [PasswordRepository], in the [ai.passman.domain.pgp.FakePgpRepository]
 * style: only the methods a test configures get behaviour, everything else fails loudly.
 */
class FakePasswordRepository(
    private val entries: () -> List<PasswordEntry> = { unsupported("getPasswordEntries") },
    private val add: suspend (AddPassword.EntryData) -> Boolean = { unsupported("addPasswordEntry") },
    private val list: suspend () -> Outcome<List<PasswordEntry>> = { Outcome.Success(entries()) },
    private val push: suspend (String) -> Outcome<Unit> = { unsupported("pushPasswordDatabase") },
    private val pull: suspend (String) -> Outcome<Unit> = { unsupported("pullPasswordDatabase") },
) : PasswordRepository {

    val added = mutableListOf<AddPassword.EntryData>()

    override suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean {
        added += entry
        return add(entry)
    }

    override suspend fun getPasswordEntries(): List<PasswordEntry> = entries()

    override suspend fun listPasswordEntries(): Outcome<List<PasswordEntry>> = list()

    override suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean = unsupported("updatePasswordEntry")
    override suspend fun deletePasswordEntry(passwordUuid: String): Boolean = unsupported("deletePasswordEntry")
    override suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int =
        unsupported("deletePasswordEntries")
    override suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit> =
        unsupported("transferPasswordDatabase")
    override suspend fun pushPasswordDatabase(hostName: String): Outcome<Unit> = push(hostName)
    override suspend fun pullPasswordDatabase(hostName: String): Outcome<Unit> = pull(hostName)

    companion object {
        private fun unsupported(name: String): Nothing =
            throw UnsupportedOperationException("FakePasswordRepository.$name was not configured for this test")
    }
}
