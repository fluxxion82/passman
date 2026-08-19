package ai.passman.platform.keyring

/**
 * At-rest storage for one account's device keyring (`keyring.pmk`).
 *
 * This is the `commonMain` contract because `LocalUserRepository` is a `commonMain` file in a module
 * that compiles `iosArm64`/`iosSimulatorArm64`; the implementation ([ai.passman.platform.keyring.KeyringStore])
 * is JVM/Android, and iOS simply registers no binding, exactly as it already does for the other
 * platform services. Nothing here may name a platform type.
 *
 * The keyring is the root of every other local secret — the identity-store password, the vault
 * wrapping key, the PQ key-file keys are all derived from the master key it holds — so the ordering
 * rules around it matter more than the API does:
 *
 * - [write] must be durable and atomic. A caller that persists a keyring and then re-keys another
 *   artifact under it is trusting that a crash cannot leave a half-written file, because a keyring
 *   that will not unwrap is an account that will not open.
 * - Nothing may be re-keyed under a master key whose keyring has not been written yet. [write] is
 *   therefore expected to throw rather than fail quietly.
 * - [delete] exists for signup rollback only. Deleting a live account's keyring destroys the account.
 *
 * ## Minting and rewrapping are different operations
 *
 * [createNew] and [write] both persist keyring bytes, and the split between them is the whole point.
 * Minting a keyring introduces a **new** master key, so it must never overwrite one that is already
 * there: the artifacts on disk are sealed under the existing key and nothing can re-derive the one
 * being replaced. Rewrapping ([write]) carries the *same* master key under a new password, so
 * replacing the file is exactly the intent.
 *
 * Two logins on one account is not hypothetical — the desktop app has no single-instance lock, so
 * it is a double-click away — and the losing side of that race must find out it lost rather than
 * write over the winner.
 *
 * ## Two generations, because a password change spans two files
 *
 * A password change rewraps the keyring and persists a new credential hash, and those are separate
 * writes with roughly half a second of Argon2id between them. A crash in that gap used to be fatal:
 * credential on the new password, keyring on the old, so credential verification rejects the old
 * password and the keyring rejects the new one and **neither opens the account**. Reversing the two
 * writes only moves the hole.
 *
 * So the rewrapped keyring is *staged* ([writeNext]) beside the live one, the credential commits, and
 * only then is the staged copy promoted ([promoteNext]). Every intermediate state has a password that
 * works: with the credential still old the live keyring opens it, and with the credential already new
 * the staged one does. Login is responsible for finishing whichever half is outstanding and for
 * clearing a staged generation that no longer belongs to anything ([deleteNext]).
 *
 * Both generations carry the *same* device master key, so promoting a staged copy can never orphan an
 * artifact sealed under the live one.
 */
interface KeyringRepository {

    /** True when a non-empty keyring exists for [username]. */
    fun exists(username: String): Boolean

    /** The stored keyring bytes, or null when this account has none yet (pre-keyring account). */
    fun read(username: String): ByteArray?

    /**
     * Durably persist [bytes] as [username]'s **first** keyring, atomically claiming the name.
     *
     * The claim and the existence check must be one indivisible operation (`O_EXCL`), not a
     * `read`-then-`write`: a concurrent login that already minted and then re-keyed the identity
     * store under its own master key would otherwise be silently overwritten, leaving a store whose
     * password nobody can derive.
     *
     * @return true when this call created the keyring; false when one already existed, in which case
     *   nothing was written and the caller **must abandon the master key it was about to install**.
     * @throws Exception if a keyring could have been created but the bytes could not be persisted.
     */
    fun createNew(username: String, bytes: ByteArray): Boolean

    /**
     * Durably and atomically replace [username]'s keyring with [bytes].
     *
     * For rewrapping an existing master key under a new password. To mint a keyring for an account
     * that has none, use [createNew] — this call will happily destroy one.
     *
     * @throws Exception if the bytes could not be persisted. Callers must treat a failure as fatal to
     *   whatever they were about to do — never as "carry on without a keyring".
     */
    fun write(username: String, bytes: ByteArray)

    /** Remove the keyring. Returns true when a file was actually removed. Signup rollback only. */
    fun delete(username: String): Boolean

    /**
     * Durably persist [bytes] as [username]'s **pending** keyring generation, replacing any previous
     * pending one.
     *
     * The live keyring is not touched, which is the entire point: until [promoteNext] runs, the
     * account still opens with the password the live keyring was wrapped under. Callers must verify
     * the staged bytes unwrap — by reading them back through [readNext] — before committing anything
     * that depends on them.
     *
     * @throws Exception if the bytes could not be persisted. A staging failure must abort the change,
     *   never continue as though it had staged.
     */
    fun writeNext(username: String, bytes: ByteArray)

    /** The pending generation's bytes, or null when there is no pending change. */
    fun readNext(username: String): ByteArray?

    /**
     * Atomically make the pending generation the live keyring, consuming it.
     *
     * Must never leave the account with no keyring at all, not even for an instant — a crash inside
     * this call has to land on either the old generation or the new one.
     *
     * @return true when a pending generation was promoted, false when there was none.
     */
    fun promoteNext(username: String): Boolean

    /**
     * Discard the pending generation.
     *
     * For a change that failed before it committed, and for the debris a crash leaves behind. A
     * staged generation that outlives its change is not inert: a later login would promote it and
     * silently move the account onto a password nobody typed.
     *
     * @return true when a pending generation was removed.
     */
    fun deleteNext(username: String): Boolean
}
