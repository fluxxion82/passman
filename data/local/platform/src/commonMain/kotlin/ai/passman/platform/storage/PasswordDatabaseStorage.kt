package ai.passman.platform.storage

/**
 * At-rest storage for one account's encrypted vault database.
 *
 * Every method here guards the single file whose loss is the product's worst outcome, so the
 * contract is written in terms of what must survive rather than what must happen.
 */
interface PasswordDatabaseStorage {
    fun exists(username: String): Boolean
    fun create(username: String, initialEncryptedBytes: ByteArray)
    fun read(username: String): ByteArray
    fun write(username: String, encryptedBytes: ByteArray)

    /**
     * Remove [username]'s vault file.
     *
     * Exists for exactly one caller: signup rollback, removing a database the same signup just
     * [create]d so a retry does not read "account exists" off the debris. It must never run against
     * a vault this flow did not create. The write-generation backup and any pre-migration copy are
     * left alone — a freshly created account has neither, and for anything older this method is the
     * wrong tool.
     */
    fun delete(username: String)

    /**
     * Keep [ciphertext] as the one-generation pre-migration copy of [username]'s vault, beside the
     * vault itself.
     *
     * This is the downgrade path. A user who installs this build, has their RSA-wrapped vault
     * rewritten as suite 5, and then rolls back to the previous build would otherwise find a vault
     * the old code cannot parse at all; the retained copy is what they restore. **The app never
     * deletes it**, and it is never rewritten — hence "one generation": the first legacy ciphertext
     * seen for an account is the one kept, because a later copy can only be *younger* than the state
     * the user is trying to get back to.
     *
     * Implementations must not overwrite an existing copy, and must publish durably: a half-written
     * downgrade copy is worse than none, since it looks like a recovery option and is not one.
     *
     * @return true when this call created the copy, false when one was already there.
     * @throws Exception if a copy is absent and could not be written. Callers treat that as fatal to
     *   the migration — converting a vault whose downgrade copy could not be written is exactly the
     *   trade this artifact exists to avoid.
     */
    fun retainPreMigration(username: String, ciphertext: ByteArray): Boolean

    /**
     * Replace [username]'s vault with [replacement], but only while it still holds exactly [expected].
     *
     * The compare and the write must be one indivisible operation **with respect to every writer that
     * can reach the same vault**, which on desktop includes a second instance of the app: it ships
     * without a single-instance lock, so in-process synchronisation alone is not enough and an
     * implementation owes this an inter-process guarantee as well (see `JvmPasswordDatabaseStorage`,
     * which takes an advisory `FileLock` and says what happens when the filesystem refuses one).
     *
     * Why it has to be indivisible: every publish in `LocalPasswordRepository` is a
     * read-modify-write spanning a decrypt, a re-encrypt and two disk round trips, and another save
     * can easily land in the middle of it. The loser would otherwise publish the entry list it read
     * *before* that save and silently discard whatever the user had just typed — on the first session
     * after an update, which is precisely when they are most likely to be typing. A conditional
     * replace makes the losing writer notice instead.
     *
     * @return true when the replacement was published, false when the vault had changed underneath —
     *   in which case nothing was written and the caller must **not** retry with the same bytes.
     */
    fun replaceIfUnchanged(username: String, expected: ByteArray, replacement: ByteArray): Boolean
}
