package ai.passman.domain.password.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.model.PasswordEntry

/**
 * Every method that names a single entry names it by [PasswordEntry.uuid], never by
 * [PasswordEntry.id]: the id is a display ordinal that the next read or merge reassigns, so a
 * mutation addressed by it can land on a different credential than the caller chose.
 */
interface PasswordRepository {
    /**
     * @return whether the new entry was actually published. The write is a conditional publish with
     * a bounded retry, so it *can* come back false — and reporting that as success is how a user
     * closes the app believing a credential was saved that never reached the disk.
     */
    suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean
    suspend fun getPasswordEntries(): List<PasswordEntry>

    /**
     * Like [getPasswordEntries] but a failed read is an [Outcome.Error]
     * ([ai.passman.domain.password.exception.PasswordFailure.VaultUnreadable]) instead of an
     * empty list. [getPasswordEntries] deliberately flattens an unreadable vault to `emptyList()`
     * for display; a caller that acts on the *absence* of an entry cannot use that answer, because
     * "the vault holds no such row" and "the vault could not be read" would look identical. A pure
     * read: never renumbers, migrates or writes anything.
     *
     * Default wraps [getPasswordEntries] so in-memory fakes keep working; real implementations
     * override it to surface the failure.
     */
    suspend fun listPasswordEntries(): Outcome<List<PasswordEntry>> = Outcome.Success(getPasswordEntries())

    /**
     * Applies [entry]'s fields to *one* vault row with the same [PasswordEntry.uuid].
     *
     * At most one, deliberately: identities derived for entries that predate the field are unique
     * only up to name and username, so a rewrite of every match could overwrite a credential the
     * caller never opened.
     *
     * @return whether the rewritten vault was published. False also covers a target that is no
     * longer in the vault: nothing was written, and saying so beats resurrecting it.
     */
    suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean

    /**
     * Removes *one* row with [passwordUuid]. A uuid that is no longer in the vault is a no-op, not a
     * delete of its neighbour.
     *
     * @return whether a row was removed and the result published. The no-op reports false.
     */
    suspend fun deletePasswordEntry(passwordUuid: String): Boolean

    /**
     * Removes at most one row per uuid in [passwordUuids].
     *
     * @return how many rows were actually removed and published. Never more than the number of
     * distinct uuids passed in, so a caller can compare it against the size of the selection it
     * offered the user.
     */
    suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int
    /**
     * One-way send to a **typed address** (Settings > Transfer), which is the only sync-adjacent
     * path with no chosen [TrustedDevice] to carry. The implementation has to resolve the address to
     * a pairing before it can pin anything, and an address that does not identify exactly one
     * pairing is refused rather than guessed at.
     */
    suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit>

    /**
     * Bilateral Sync Mode push/pull, against the [TrustedDevice] record the user chose.
     *
     * The record, not its [TrustedDevice.lastHost]: the transport pins the peer's SPKI from the
     * device it is handed, and re-deriving that device from an address is a first-match lookup over
     * a field two pairings can legitimately share. Pinning the wrong one of two same-host pairings
     * fails the handshake outright, which is how editing the address of the *correct* device could
     * leave sync permanently broken for it.
     */
    suspend fun pushPasswordDatabase(device: TrustedDevice): Outcome<Unit>
    suspend fun pullPasswordDatabase(device: TrustedDevice): Outcome<Unit>
}
