package ai.passman.domain.password

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.repository.PasswordRepository

/**
 * Hand-written stand-in for [PasswordRepository], in the [ai.passman.domain.pgp.FakePgpRepository]
 * style: only the methods a test configures get behaviour, everything else fails loudly.
 */
class FakePasswordRepository(
    private val entries: () -> List<PasswordEntry> = { unsupported("getPasswordEntries") },
    private val add: suspend (AddPassword.EntryData) -> Boolean = { unsupported("addPasswordEntry") },
    private val push: suspend (TrustedDevice) -> Outcome<Unit> = { unsupported("pushPasswordDatabase") },
    private val pull: suspend (TrustedDevice) -> Outcome<Unit> = { unsupported("pullPasswordDatabase") },
) : PasswordRepository {

    val added = mutableListOf<AddPassword.EntryData>()

    override suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean {
        added += entry
        return add(entry)
    }

    override suspend fun getPasswordEntries(): List<PasswordEntry> = entries()

    override suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean = unsupported("updatePasswordEntry")
    override suspend fun deletePasswordEntry(passwordUuid: String): Boolean = unsupported("deletePasswordEntry")
    override suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int =
        unsupported("deletePasswordEntries")
    override suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit> =
        unsupported("transferPasswordDatabase")
    override suspend fun pushPasswordDatabase(device: TrustedDevice): Outcome<Unit> = push(device)
    override suspend fun pullPasswordDatabase(device: TrustedDevice): Outcome<Unit> = pull(device)

    companion object {
        private fun unsupported(name: String): Nothing =
            throw UnsupportedOperationException("FakePasswordRepository.$name was not configured for this test")
    }
}
