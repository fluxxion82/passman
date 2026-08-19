package ai.passman.platform.service

import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.domain.base.model.Outcome

/**
 * ## Why three of these take [IdentityStorePassword] and one takes a `String`
 *
 * [createKeystoreForUser], [changeKeystorePassword] and [reencodeIdentityStoreIfLegacy] all **write**
 * the identity store, and they write it at a negligible PKCS#12 work factor. That is only sound for a
 * password nobody can guess, so they demand the type whose sole production source is the keyring
 * derivation (`VaultCipher.identityStorePassword`) — the invariant is in the signature rather than in
 * a paragraph a future caller will not read.
 *
 * [canOpenKeystore] keeps a plain `String` because it genuinely has to try the **login** password: on
 * a pre-keyring account that is what opens the store, and asking is the first thing login does. A
 * probe chooses no parameters and writes no bytes, so there is nothing there to downgrade.
 */
interface KeystoreLifecycle {
    suspend fun createKeystoreForUser(username: String, keystoreDir: String, password: IdentityStorePassword): Result<Unit>
    suspend fun changeKeystorePassword(
        username: String,
        keystoreDir: String,
        oldPassword: String,
        newPassword: IdentityStorePassword,
    ): Outcome<Unit>

    /**
     * Rewrite [username]'s identity store at cheap password-based parameters, if it is not already
     * there. A no-op, and a cheap one, when it is.
     *
     * ## Why this exists
     *
     * A PKCS#12's PBE and MAC iteration counts are paid in full on **every** open, and login opens the
     * store. BouncyCastle's defaults are 600,000 for the bags and 1,200,000 for the MAC, which is
     * seconds on a phone. Those counts buy security only against *guessing the password*, and since
     * the keyring landed the store's password is 256 bits of HKDF output from the device master key —
     * there is nothing to guess. So for this file, and only this file, the work factor is pure cost.
     *
     * Accounts created or migrated before the low-parameter writer are still carrying the expensive
     * ones, and this is what moves them over, once, on their next login.
     *
     * ## The precondition, which is not optional
     *
     * [password] is an [IdentityStorePassword] and that is load-bearing, not decoration. A store still
     * sealed with the login password is guessable, its iteration count is the only thing making
     * guessing expensive, and rewriting it cheaply would be a downgrade attack performed by the app on
     * its own user. The type makes the login password unable to reach this method; the caller still
     * has to check that the store is *actually on* the derived password, because holding the derived
     * value proves nothing about what the file is currently sealed with. The un-migrated case belongs
     * to [changeKeystorePassword].
     *
     * Failure is never fatal: the store is left exactly as it was and the next login tries again.
     */
    suspend fun reencodeIdentityStoreIfLegacy(
        username: String,
        keystoreDir: String,
        password: IdentityStorePassword,
    ): Outcome<Unit>

    /**
     * True when [username]'s identity store exists and its private key can actually be unwrapped with
     * [password].
     *
     * Login needs to know *which* password currently opens the store — the keyring-derived one, or
     * the login password on an account that predates the keyring, or neither on a damaged store —
     * before it changes anything, because the alternative is discovering it by attempting the change
     * and reading the failure. That distinction is the whole of the migration state machine, so it
     * gets an explicit question rather than an inferred one.
     *
     * ## The one way this is not a pure question
     *
     * Being the first thing login asks of the store makes it the only place a crashed commit's
     * recovery copy can be noticed before anything depends on the store opening. So when the answer
     * would be `false` **because the live store is structurally unreadable** and a backup beside it
     * verifies under [password], the backup is put back and the question re-asked. Nothing is
     * restored over a store that is intact, and a backup that does not verify is left untouched — see
     * `KeystoreClient.restoreIdentityKeyStoreFromBackup`.
     *
     * Never throws: an unreadable, missing or wrong-password store is `false`.
     */
    suspend fun canOpenKeystore(username: String, keystoreDir: String, password: String): Boolean

    /**
     * True when [username]'s identity store is present on disk, whatever password it is under.
     *
     * [canOpenKeystore] cannot answer this: it returns false both for "no store" and for "a store
     * this password does not open", and those demand opposite actions. Two callers need the
     * distinction:
     *
     * - **Login**, before minting a keyring for an account that appears not to have one. A store
     *   that exists but opens with neither the login password nor a derived one belongs to a master
     *   key this process cannot reproduce — another login already migrated it — and minting would
     *   overwrite that keyring and strand the store forever. No store at all is the ordinary
     *   pre-keyring state and minting is correct.
     * - **Signup**, which used to gate on the vault database alone and so would happily recreate an
     *   account whose database was gone but whose keystore directory survived — exactly what
     *   restoring a backup of the vault directory leaves behind.
     */
    suspend fun identityStoreExists(username: String, keystoreDir: String): Boolean

    /**
     * Delete [username]'s identity store — and the lock file that guards it — and then its account
     * directory if that leaves it empty.
     *
     * Signup rollback only, and deliberately non-recursive: a rollback that removed the directory
     * tree would take `hybrid.key` and `mldsa.key` with it, and those belong to an account that a
     * failed signup has no business owning. Returns true when the `.pfx` was removed.
     */
    suspend fun deleteKeystoreForUser(username: String, keystoreDir: String): Boolean
}
