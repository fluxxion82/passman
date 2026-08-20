package ai.passman.platform.repository

import ai.passman.cache.di.passmanSessionScope
import ai.passman.crypto.CryptoKey
import ai.passman.crypto.kdf.PasswordHasher
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.crypto.SecureRandomService
import ai.passman.platform.keyring.KeyringRepository
import ai.passman.platform.service.KeystoreLifecycle
import ai.passman.platform.service.PgpKeyRingService
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.vault.PortableVaultFormat
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.exception.Failure
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.models.KdfParams
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.koin.core.parameter.parametersOf
import org.koin.core.qualifier.named
import org.koin.core.scope.Scope
import org.koin.mp.KoinPlatform

private const val SALT_BYTES = 48

/**
 * Account bootstrap: signup, login, and the migration that moves an existing account's PKCS#12
 * identity store off the login password.
 *
 * ## Why the identity store moved
 *
 * The `.pfx` lives in the same copyable directory as the vault and used to be sealed with the login
 * password under Bouncy Castle's PKCS#12 PBE — SHA-1 based, ~600k iterations, **not** memory-hard.
 * Making the vault Argon2id-gated while leaving the `.pfx` on the same password raises nothing: an
 * attacker with the data directory attacks the cheap KDF, recovers the password, and runs Argon2id
 * once. So the store's password is now 256 bits derived from the device master key
 * ([VaultCipher.identityStorePassword]) and is not guessable at any cost. The login password gates
 * exactly one thing: the keyring.
 *
 * ## Ordering rules (these are the whole risk of this class)
 *
 * Every path below is written so that **either the login password or the derived password always
 * opens the `.pfx`**, and so that a crash between any two steps leaves an account that opens on the
 * next login and completes what was interrupted.
 *
 * - **Signup** creates the keyring *first* and only then derives the store password and creates the
 *   `.pfx` under it. Anything that fails after the keyring exists rolls the whole account back, so a
 *   retry starts from nothing rather than from a store whose password nobody holds.
 * - **Login** never changes the store password before the keyring is safely on disk. The keyring is
 *   written and only afterwards is the store re-keyed, so the failure ordering is
 *   `no keyring, store on login password` → `keyring, store on login password` → `keyring, store on
 *   derived password`. Every one of those three states is fully usable and the middle one resumes.
 * - A `changeKeystorePassword` failure is loud but **not** fatal: login continues with the login
 *   password and the migration retries next time. It must never half-apply.
 *
 * ## Two logins at once
 *
 * The desktop app has no single-instance lock, so two logins on one account are a double-click
 * away, and the dangerous one is two *first* logins on a pre-keyring account. Both would read "no
 * keyring", both would mint a master key, and the loser's write would land on top of the winner's
 * keyring after the winner had already re-keyed the identity store — a `.pfx` sealed under a master
 * key that exists nowhere, with both logins reporting success. Two things stop it, and they are
 * deliberately independent:
 *
 * 1. [openOrCreateKeyring] settles *whether minting is safe at all* before it mints. An identity
 *    store that exists but opens with neither the login password nor the derived one has already
 *    been migrated by somebody else; this login refuses rather than replacing their keyring.
 * 2. [ai.passman.platform.keyring.KeyringRepository.createNew] claims the file with `O_EXCL`, so
 *    even two logins that both pass (1) before either writes cannot both win. The loser is told and
 *    discards its master key.
 *
 * ## Cost
 *
 * **One keyring operation per login**, plus the credential check. Stated that way on purpose: the
 * keyring operation is `unwrap` on an established account but `create` on the first login of one
 * that predates the keyring, and the credential check is one Argon2id on a current credential but a
 * PBKDF2 verify *plus* an Argon2id rehash on a legacy one. The budget the design cares about — no
 * more than two memory-hard derivations, and no cheaper KDF anywhere over the same password —
 * survives all four combinations, and "one keyring operation" is what the test actually counts.
 * Nothing else in the system derives from the login password.
 */
@OptIn(ExperimentalEncodingApi::class)
class LocalUserRepository(
    private val platform: Platform,
    private val coroutinesContextFacade: CoroutinesContextFacade,
    private val userPreferences: UserPreferences,
    private val keystoreLifecycle: KeystoreLifecycle,
    private val pgpKeyRingService: PgpKeyRingService,
    private val storage: PasswordDatabaseStorage,
    private val passwordHasher: PasswordHasher,
    private val secureRandom: SecureRandomService,
    private val biometricUnlock: BiometricUnlock,
    private val keyringRepository: KeyringRepository,
    private val vaultCipher: VaultCipher,
    private val portableVaultFormat: PortableVaultFormat? = null,
) : UserRepository, BiometricUnlockRepository {

    private val keystoreDir = "${platform.getLocalPath()}/keystore/"
    private val pgpDir = "${platform.getLocalPath()}/pgp/"

    /**
     * The default PGP rings are sealed with [pgpPassphrase], never with the login password: PGP
     * S2K is a cheap KDF and the ring files leave the device (sync, share, export), so a cracked
     * ring must not yield the vault login. The passphrase is generated by `SignUpUser` — which
     * records it as the "passman pgp" vault entry after this returns, the vault session not being
     * bound until the end of [bootstrapAccount] — and accounts that predate the decoupling keep
     * their login-password rings (the PGP change-password screen is their migration path; a
     * password change never touches the rings either way, see [changeUserPassword]).
     */
    override suspend fun signup(username: String, password: String, pgpPassphrase: String): Outcome<AppUser> = withContext(coroutinesContextFacade.io) {
        // Before anything is created. The old order created the keystore and *then* checked for an
        // existing account, which already clobbered a live account's .pfx on a name collision; with
        // rollback in the picture that would now also delete it.
        if (accountExists(username)) {
            return@withContext Outcome.Error("account exists", AuthFailure.AccountAlreadyExists)
        }

        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            coroutineScope {
                // Ring generation is seconds of keygen CPU and independent of everything else in
                // the bootstrap, so it runs concurrently with the vault init and the credential
                // hash and is awaited in beforeCommit — a failure still rolls the whole account
                // back exactly as it did when the steps were sequential. An early bootstrap
                // failure lets the generation finish before this scope returns; the rollback
                // touches the keystore and keyring directories, never `pgp/`, and an orphaned
                // ring pair is simply overwritten by the next signup of the name.
                var pgpRings: Deferred<Result<Unit>>? = null
                bootstrapAccount(
                    scope,
                    username,
                    password,
                    afterIdentityStore = { storePassword ->
                        pgpRings = async { pgpKeyRingService.createKeyRings(username, pgpPassphrase, pgpDir) }
                        warmIdentityKeys(scope, username, storePassword)
                        null
                    },
                    beforeCommit = {
                        val created = pgpRings
                        val ringsOk = created != null && runCatching { created.await().isSuccess }.getOrElse {
                            if (it is CancellationException) throw it
                            false
                        }
                        if (ringsOk) {
                            null
                        } else {
                            Outcome.Error("failed to create key rings", AuthFailure.PgpKeyRingCreationFailure)
                        }
                    },
                )
            }
        } ?: Outcome.Error("Failed to create scope", AuthFailure.SignupFailure)
    }

    override suspend fun login(username: String, password: String): Outcome<AppUser> = withContext(coroutinesContextFacade.io) {
        KLogger.d { "login: username=$username" }

        val storedCredentials = when (val verified = verifiedCredentials(username, password)) {
            is Outcome.Error -> return@withContext verified
            is Outcome.Success -> verified.value
        }

        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            openSession(scope, username, password) {
                Outcome.Success(AppUser.LoggedIn(userName = username, password = storedCredentials))
            }
        } ?: Outcome.Error("Failed to create scope", AuthFailure.LoginFailure)
    }

    /**
     * Recover the master password from the account's biometric enrolment and then log in with it.
     *
     * The second line is the whole method, and it is deliberately a call to [login] rather than a
     * copy of it. The version this replaced differed from [login] by one line — it demanded the
     * typed password *as well* as a fingerprint, and the fingerprint result was a boolean nothing
     * cryptographic depended on. So the feature was a second factor pretending to be a first, and
     * the login path had a fork whose only distinguishing behaviour was an extra prompt.
     *
     * Delegating means every property of a password login holds here without being restated:
     * the credential check, the legacy-KDF upgrade, the staged-keyring resume, the identity-store
     * migration, the throttle upstream. It also means a **stale** wrapped password (changed on
     * another device, synced here) fails the ordinary credential check instead of being trusted.
     *
     * The only method here without a `withContext(io)` wrapper, and deliberately: the recovery ends
     * in a system prompt that has to run on the main thread, so it dispatches itself, and [login]
     * takes the IO hop for the half that needs it.
     */
    override suspend fun bioLogin(username: String): Outcome<AppUser> {
        val password = when (val unlocked = biometricUnlock.unlock(username)) {
            is Outcome.Error -> return unlocked
            is Outcome.Success -> unlocked.value
        }
        return login(username, password)
    }

    /**
     * Enrolling is the one moment a copy of the master password is made, so it happens only after
     * [verifiedCredentials] has said the caller knows it — which is also what makes the settings
     * screen, and not the login screen, the right place to offer this. A login screen has a
     * *claimed* password; verifying it there to enrol would be an oracle that answers "is this the
     * password?" without signing anybody in.
     */
    override suspend fun enable(username: String, password: String): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        when (val verified = verifiedCredentials(username, password)) {
            is Outcome.Error -> verified
            is Outcome.Success -> biometricUnlock.enroll(username, password)
        }
    }

    override suspend fun disable(username: String) = biometricUnlock.disable(username)

    override suspend fun biometricUnlockState(username: String): BiometricUnlockState =
        biometricUnlock.state(username)

    /**
     * A password change rewraps `keyring.pmk` and nothing else.
     *
     * The identity store, the vault and the PQ key files all hang off the device master key, and the
     * master key does not rotate — only the Argon2id wrapping around it does. So the vault database
     * bytes, `hybrid.key`, `mldsa.key` and the `.pfx` are all byte-identical before and after, which
     * is what removes the old multi-artifact ordering problem and the lockout it caused.
     *
     * ## Why this is three steps and not one
     *
     * Two facts have to move together and cannot: the credential hash in preferences, and the keyring
     * on disk. Between them sit a full `rewrapSession` (Argon2id, 64 MiB), an `unlockSession` to
     * verify it, and a `hashPassword` — roughly half a second of CPU-heavy work, and on Android a
     * backgrounded password-change screen is a plausible low-memory-killer target.
     *
     * Write the keyring first and crash before the credential lands, and you get credential=old /
     * keyring=new: `verifiedCredentials(old)` passes and `unlockSession(keyring, old)` throws, while
     * the new password never gets past credential verification. **Neither password opens the
     * account.** Doing it the other way round produces the mirror image of the same hole. It also
     * fires without a crash at all, if the credential write merely *fails* after the keyring landed.
     *
     * The fix is a second generation, not a different order:
     *
     * 1. stage the rewrapped keyring as `keyring.pmk.next`, leaving the live one alone;
     * 2. commit the new credential;
     * 3. promote the staged generation over the live keyring.
     *
     * After (1) the old password still opens everything. After (2) the new password verifies and the
     * staged generation opens the account, which is what [openOrCreateKeyring] resumes from. After
     * (3) it is an ordinary account again. There is no instant at which no password works.
     *
     * The credential is committed *here* rather than by `ChangeUserPassword`, which normally upserts
     * what this returns: that upsert happens after this method has returned, far too late to order a
     * promotion against. The use case's upsert then repeats a value already on disk, which is a
     * no-op.
     *
     * Costs four Argon2id derivations, not one: verifying [oldPassword], rewrapping under
     * [newPassword], unwrapping the result to prove it opens, and hashing the new credential. The
     * two-derivation budget is the *login* path's; a password change happens once in a while, and the
     * read-back in particular is worth far more than the second of latency it costs.
     */
    override suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser> = withContext(coroutinesContextFacade.io) {
        val user = userPreferences.getUser() as? AppUser.LoggedIn
            ?: return@withContext Outcome.Error("not signed in", AuthFailure.GeneralAuthFailure("not signed in"))

        // Check the old password explicitly. It used to be checked only as a side effect of unlocking
        // the identity store with it, and that side effect is gone: the store's password is derived
        // from a master key that is already unwrapped in this session, so without this every path
        // below would succeed for someone at an unlocked screen who does not know the current
        // password.
        val previousCredential = when (val verified = verifiedCredentials(user.userName, oldPassword)) {
            is Outcome.Error -> return@withContext verified
            is Outcome.Success -> verified.value
        }

        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val sessionKey = vaultSession(scope).current
                ?: return@passmanSessionScope Outcome.Error("no vault session", AuthFailure.GeneralAuthFailure("not signed in"))

            // If the store somehow never migrated, finish that first. Persisting a new credential
            // while the store is still on the *old* login password would strand it: after the
            // change, neither the derived password nor the new login password opens it.
            val storePassword = resolveIdentityStorePassword(user.userName, sessionKey, oldPassword)
            if (storePassword != vaultCipher.identityStorePassword(sessionKey).value) {
                KLogger.e { "changeUserPassword: identity store is not on the derived password - aborting" }
                return@passmanSessionScope Outcome.Error(
                    "keystore password change failed",
                    AuthFailure.KeystoreCreationFailure,
                )
            }

            if (!keyringRepository.exists(user.userName)) {
                return@passmanSessionScope Outcome.Error("no keyring", AuthFailure.GeneralAuthFailure("keyring missing"))
            }

            // Everything from here to the promotion runs to completion even if the caller is
            // cancelled. The three steps below are one change spread over two files, and each of
            // them is separated from the next by hundreds of milliseconds of Argon2id — which is
            // exactly the window in which a user who taps "log out" (or backgrounds the app on
            // Android) tears down the scope this is running in. The cancellation is delivered at the
            // next suspension point, which is the credential write, and the flow's own error
            // handling then does precisely the wrong thing with it: it reports "could not persist
            // the new credential", discards the staged keyring and returns an error nobody is left
            // to read, so the password silently did not change. Every state this section passes
            // through is recoverable by the next login, but only if it is allowed to reach one.
            //
            // The pre-flight above stays cancellable on purpose: it verifies the old password and
            // resolves (and if need be migrates) the identity-store password, and none of it is part
            // of the two-file change. Its one write, `changeKeystorePassword`, is already documented
            // as retried on the next login and half-applies no more here than it does on the login
            // path it shares.
            withContext(NonCancellable) {
                // Step 1. Nothing the account depends on has moved yet, so every failure below this
                // point and above the commit is undone by deleting one file.
                val staged = runCatching {
                    val bytes = vaultCipher.rewrapSession(sessionKey, newPassword)
                    keyringRepository.writeNext(user.userName, bytes)
                    // Read back and unwrap before anything is committed against it: a staged
                    // generation the new password cannot open must never become the live keyring.
                    // Comparing the derived store password is a master-key equality check that never
                    // exposes the key.
                    val readBack = keyringRepository.readNext(user.userName)
                        ?: error("the staged keyring vanished")
                    val verified = vaultCipher.unlockSession(readBack, newPassword)
                    try {
                        check(vaultCipher.identityStorePassword(verified).value == storePassword) {
                            "the staged keyring holds a different device master key"
                        }
                    } finally {
                        verified.destroy()
                    }
                    readBack
                }
                staged.exceptionOrNull()?.let { failure ->
                    KLogger.e(failure) { "changeUserPassword: staging the rewrapped keyring failed - discarding it" }
                    discardStagedKeyring(user.userName)
                    return@withContext Outcome.Error("keyring rewrap failed", AuthFailure.GeneralAuthFailure("keyring rewrap failed"))
                }
                val stagedBytes = staged.getOrThrow()

                // Step 2. The commit. Both generations are on disk while this runs, so a crash inside
                // it lands on a state the next login can finish either way.
                val changed = buildLoggedInUser(user.userName, newPassword)
                val committed = runCatching { userPreferences.upsert(changed) }
                committed.exceptionOrNull()?.let { failure ->
                    KLogger.e(failure) { "changeUserPassword: could not persist the new credential - discarding the staged keyring" }
                    discardStagedKeyring(user.userName)
                    return@withContext Outcome.Error(
                        "failed to persist the new credential",
                        AuthFailure.GeneralAuthFailure("failed to persist the new credential"),
                    )
                }

                // Step 3. Promote, and *prove* it landed.
                //
                // A crash here is survivable — login resumes from credential-new/keyring-old. A
                // silent failure is not, and there is a concurrent one: a second login on this
                // account sees a live keyring that still opens with the old password, treats the
                // staged generation as debris from an abandoned change, and deletes it.
                // `promoteNext` then finds nothing to promote and reports it, and the account is left
                // with a credential on the new password and a keyring on the old — the
                // both-passwords-fail state, reached from the other direction. So the promotion is
                // checked by comparing bytes (free, and stronger than a second unwrap: these exact
                // bytes were already proven to open with the new password), retried once, and only
                // then given up on.
                if (!promoteAndConfirm(user.userName, stagedBytes)) {
                    KLogger.e { "changeUserPassword: the staged keyring did not become live - restoring the previous credential" }
                    // The live keyring is still the old one, so putting the credential back makes the
                    // account open with the old password again. Leaving it would strand both.
                    val rolledBack = restoreCredential(user.userName, committed = changed.password, previous = previousCredential)
                    // Only once the credential is demonstrably back on the old password is the staged
                    // generation debris. If the rollback did not happen — because the write failed, or
                    // because the credential on disk is no longer the one this flow wrote — then the
                    // account is on a password that only the staged keyring opens, and deleting it
                    // here is the both-passwords-fail state arrived at from a third direction.
                    if (rolledBack) discardStagedKeyring(user.userName)
                    return@withContext Outcome.Error(
                        "keystore password change failed",
                        AuthFailure.GeneralAuthFailure("could not promote the rewrapped keyring"),
                    )
                }

                // The wrapped copy holds the password that was just retired. Two reasons it goes,
                // and the second is the one that matters: it would hand out a string that no longer
                // verifies (a login that fails for no visible reason), and until the user noticed,
                // the *old* master password would still be recoverable from this device with a
                // fingerprint — after they had deliberately rotated it. Only a change that got all
                // the way here clears it; every failure path above leaves the old password current
                // and the enrolment correct.
                //
                // Best-effort by design: the change has already committed and cannot be undone by a
                // preferences write that failed, so a failure here is logged inside disable().
                biometricUnlock.disable(user.userName)

                Outcome.Success(changed)
            }
        } ?: Outcome.Error("Failed to create scope", AuthFailure.SignupFailure)
    }

    override suspend fun logout() {
        val sessionScope = KoinPlatform.getKoin()
            .getOrCreateScope("session-${userPreferences.getSessionId()}", named("sessionScope"))
        // Closing the scope fires the VaultSession onClose callback, which zeroes the master key.
        sessionScope.close()
    }

    /**
     * Verify [password] against the stored credential and transparently upgrade a weaker KDF.
     *
     * Unchanged in substance from before the keyring: this is the first of the two memory-hard
     * derivations per login, and it still runs *before* anything touches the keystore, because a
     * wrong-password keystore unlock surfaces as a null Koin instance and an NPE inside
     * `ScopedInstanceFactory`, which is too generic to translate into a useful message.
     */
    private suspend fun verifiedCredentials(username: String, password: String): Outcome<Password> {
        val storedCredentials = userPreferences.getStoredCredentials(username)
        if (storedCredentials == null) {
            KLogger.w { "login: no stored credentials for $username" }
            return Outcome.Error("No account", AuthFailure.NoStoredCredentials)
        }

        val passwordOk = runCatching {
            verifyPassword(storedCredentials, password)
        }.getOrElse {
            KLogger.e(it) { "login: failed to verify password hash — ${it::class.simpleName}: ${it.message}" }
            return Outcome.Error("Auth failed", AuthFailure.GeneralAuthFailure(it.message ?: "Auth failed"))
        }

        if (!passwordOk) {
            KLogger.w { "login: hash mismatch — invalid password" }
            return Outcome.Error("Password is incorrect", AuthFailure.InvalidPassword)
        }

        return Outcome.Success(maybeUpgradeKdf(username, password, storedCredentials))
    }

    /**
     * Does anything belonging to [username] already exist?
     *
     * All three artifacts, not just the vault database. Gating on the database alone let a signup
     * run against an account whose database was gone but whose `keystore/<user>/` directory
     * survived — the state a restore drill produces, and the state a user reaches by deleting the
     * vault to "start over". The signup would then mint a fresh master key while `hybrid.key` and
     * `mldsa.key` stayed wrapped under the old one and the pre-existing `.pfx` sat there under an
     * RSA identity nothing could reach. After Task 6 hangs the PQ key files off the master key, that
     * orphaning becomes the normal outcome rather than an unlucky one.
     */
    private suspend fun accountExists(username: String): Boolean =
        storage.exists(username) ||
            keyringRepository.exists(username) ||
            keystoreLifecycle.identityStoreExists(username, keystoreDir)

    /**
     * Create a brand-new account. [afterIdentityStore] runs once the keyring and the `.pfx` exist and
     * returns non-null to abort; anything it aborts on, or throws, rolls the account back.
     * [beforeCommit] runs after the vault and credential exist but before the account is declared
     * complete — it is where work [afterIdentityStore] started concurrently is awaited and judged,
     * and a non-null return rolls the account back like any other failure.
     *
     * The keyring is step one and the rollback is unconditional after it, because the state this
     * guards against is an identity store sealed with a derived password whose master key was never
     * persisted — unopenable by any password, forever.
     *
     * It is minted with `createNew`, so a signup that races another signup (or a login mid-migration)
     * onto the same username loses the name rather than the account: the rollback below must never
     * run against artifacts this call did not create, which is why a lost claim returns *before* the
     * `try`.
     */
    private suspend fun bootstrapAccount(
        scope: Scope,
        username: String,
        password: String,
        afterIdentityStore: suspend (storePassword: String) -> Outcome<AppUser>?,
        beforeCommit: suspend () -> Outcome<AppUser>? = { null },
    ): Outcome<AppUser> {
        val created = runCatching { vaultCipher.createSession(password) }.getOrElse {
            KLogger.e(it) { "signup: could not create the device keyring" }
            return Outcome.Error("failed to create keyring", AuthFailure.SignupFailure)
        }
        val claimed = runCatching { keyringRepository.createNew(username, created.keyringBytes) }
        if (claimed.getOrNull() != true) {
            created.sessionKey.destroy()
            claimed.exceptionOrNull()?.let { failure ->
                KLogger.e(failure) { "signup: could not persist the device keyring" }
                return Outcome.Error("failed to create keyring", AuthFailure.SignupFailure)
            }
            KLogger.w { "signup: $username already has a keyring — refusing to replace it" }
            return Outcome.Error("account exists", AuthFailure.AccountAlreadyExists)
        }

        var complete = false
        var dbCreated = false
        try {
            val storePassword = vaultCipher.identityStorePassword(created.sessionKey)

            val keystoreCreate = keystoreLifecycle.createKeystoreForUser(username, keystoreDir, storePassword)
            if (keystoreCreate.isFailure) {
                return Outcome.Error("failed to create keystore", AuthFailure.KeystoreCreationFailure)
            }

            afterIdentityStore(storePassword.value)?.let { return it }

            initDatabase(username, created.sessionKey)?.let { failure ->
                return Outcome.Error("account exists", failure)
            }
            dbCreated = true

            // Build the credential *before* declaring the account complete: hashPassword runs
            // Argon2id and can fail, and a failure there has to roll back like any other.
            val user = buildLoggedInUser(username, password)
            beforeCommit()?.let { return it }
            vaultSession(scope).bind(created.sessionKey)
            complete = true
            KLogger.d { "signup: account bootstrapped for $username" }
            return Outcome.Success(user)
        } finally {
            if (!complete) rollbackAccount(scope, username, created.sessionKey, deleteDatabase = dbCreated)
        }
    }

    /**
     * Unlock (or bootstrap) the keyring, put the identity store on the derived password, warm the RSA
     * session keys and bind the session. [onSuccess] builds the result only once all of that held.
     */
    private suspend fun openSession(
        scope: Scope,
        username: String,
        password: String,
        onSuccess: () -> Outcome<AppUser>,
    ): Outcome<AppUser> {
        val sessionKey = runCatching { openOrCreateKeyring(username, password) }.getOrElse {
            KLogger.e(it) { "login: could not open the device keyring — ${it::class.simpleName}" }
            return Outcome.Error("Keyring unlock failed", AuthFailure.GeneralAuthFailure(it.message ?: "keyring unlock failed"))
        }

        var bound = false
        try {
            val storePassword = resolveIdentityStorePassword(username, sessionKey, password)
            warmIdentityKeys(scope, username, storePassword)
            maybeReencodeIdentityStore(username, sessionKey, storePassword)
            vaultSession(scope).bind(sessionKey)
            bound = true
            KLogger.d { "login: keys warmed — success" }
            return onSuccess()
        } catch (throwable: Throwable) {
            KLogger.e(throwable) { "login: keystore unlock failed despite valid password — ${throwable::class.simpleName}" }
            return Outcome.Error(
                "Keystore unlock failed",
                AuthFailure.GeneralAuthFailure(throwable.message ?: "keystore unlock failed"),
            )
        } finally {
            // Never leave live key material behind on a failed login.
            if (!bound) sessionKey.destroy()
        }
    }

    /**
     * The keyring for [username], creating one on the first login of an account that predates it.
     *
     * A create-and-persist failure propagates on purpose. Continuing without a persisted keyring
     * would risk re-keying the identity store under a master key that exists only in memory, which is
     * the one unrecoverable outcome this whole design is arranged to prevent.
     *
     * ## Why the store is inspected before a keyring is minted
     *
     * Reading "no keyring" and minting one is only safe while the identity store is still on the
     * login password (or absent). Between those two facts sits a `createSession` — Argon2id at
     * 64 MiB, hundreds of milliseconds — and that is more than enough room for a second login to
     * mint its own master key, write it, and re-key the store under it. Resuming here with the stale
     * answer would overwrite the winner's keyring while the store stayed sealed under the winner's
     * master key: an account that opens for nobody, from two logins that both returned success.
     *
     * So the question "is this account still un-migrated?" is asked *after* the read and *before*
     * the mint, and a store that opens with neither password means the answer changed underneath us.
     * The same guard covers a zero-length keyring on an already-migrated account, which
     * [ai.passman.platform.keyring.KeyringRepository.read] deliberately reports as absent: the file
     * says "no keyring" but the store says otherwise, and the store is the one that cannot be
     * regenerated.
     *
     * This is a check against a *moving* target, so it is not sufficient on its own — two logins can
     * both pass it before either writes. `createNew` is the part that cannot be raced.
     *
     * ## Finishing an interrupted password change
     *
     * A password change stages its rewrapped keyring as `keyring.pmk.next` and promotes it only after
     * the new credential is committed, so this is where an interrupted one gets finished. Both
     * generations hold the same device master key, which is what makes every branch below safe: a
     * staged generation that opens is *this account's* keyring under a different password, never
     * another key.
     *
     * - Live keyring opens → an ordinary login. Any staged generation is debris from a change that
     *   never committed; it is deleted, because a `.next` that outlives its change would be promoted
     *   by some later login and quietly move the account onto a password nobody typed.
     * - Live keyring refuses this password but the staged one accepts it → the crash landed between
     *   the credential commit and the promotion. Finish the promotion and carry on.
     * - No live keyring at all but a staged one that opens → a promotion that lost its target.
     *   Consulted *before* minting, because minting here would install a master key the `.pfx` never
     *   accepts, over the exact spot a restore has to go.
     */
    private suspend fun openOrCreateKeyring(username: String, password: String): VaultSessionKey {
        keyringRepository.read(username)?.let { live ->
            val opened = runCatching { vaultCipher.unlockSession(live, password) }
            opened.getOrNull()?.let { sessionKey ->
                discardStagedKeyring(username)
                return sessionKey
            }
            // The live keyring did not open. Either the password is wrong, or a password change
            // committed its credential and never got to promote. Only the staged generation can tell
            // the two apart, and it answers with the password the user just typed.
            resumeStagedKeyring(username, password)?.let { return it }
            throw opened.exceptionOrNull() ?: IllegalStateException("keyring unlock failed")
        }

        resumeStagedKeyring(username, password)?.let { return it }

        if (keystoreLifecycle.identityStoreExists(username, keystoreDir) &&
            !keystoreLifecycle.canOpenKeystore(username, keystoreDir, password)
        ) {
            KLogger.e {
                "login: $username has no readable keyring but an identity store the login password " +
                    "does not open — refusing to mint a master key that would strand it"
            }
            error("the identity store for $username is sealed under a master key this keyring cannot produce")
        }

        KLogger.d { "login: no keyring for $username — bootstrapping one" }
        val created = vaultCipher.createSession(password)
        val claimed = runCatching { keyringRepository.createNew(username, created.keyringBytes) }
        if (claimed.getOrNull() != true) {
            created.sessionKey.destroy()
            claimed.exceptionOrNull()?.let { throw it }
            // Another login minted first. Its keyring is the account's now, and the store may
            // already be re-keyed under it; the only safe move is to drop this master key and let
            // the user sign in again against the keyring that won.
            error("another sign-in created the keyring for $username first")
        }
        return created.sessionKey
    }

    /**
     * Make [stagedBytes] the live keyring, confirming by content and retrying once.
     *
     * The confirmation is a byte comparison rather than another unwrap, and that is the stronger
     * check as well as the free one: these exact bytes were unwrapped with the new password a moment
     * ago, so "the live keyring is these bytes" *is* "the live keyring opens with the new password",
     * without a second Argon2id. It also succeeds when a concurrent login promoted the same
     * generation first, which is a correct outcome and not a failure.
     *
     * Every disk call here is caught, including the confirming read. Letting that one throw would
     * abandon `changeUserPassword` by exception at the one point where the change may well have
     * *landed*, reporting a completed password change as a crash and skipping the rollback decision
     * entirely. When the move itself reported success and only the confirmation could not be read,
     * that is taken as landed: `promoteNext` returning true means the staged generation is gone
     * because it *became* the live keyring, so the account is on the new password and rolling the
     * credential back would put it on one the live keyring no longer accepts.
     */
    private suspend fun promoteAndConfirm(username: String, stagedBytes: ByteArray): Boolean {
        repeat(2) { attempt ->
            val promoted = runCatching { keyringRepository.promoteNext(username) }
                .onFailure { KLogger.e(it) { "changeUserPassword: promoting the staged keyring threw" } }
                .getOrDefault(false)
            val live = runCatching { keyringRepository.read(username) }
            if (live.getOrNull().contentEquals(stagedBytes)) return true
            live.exceptionOrNull()?.let { failure ->
                KLogger.e(failure) { "changeUserPassword: could not read back the live keyring" }
                if (promoted) {
                    KLogger.w { "changeUserPassword: the promotion reported success; treating it as landed" }
                    return true
                }
            }
            KLogger.e { "changeUserPassword: the staged keyring did not become live (attempt ${attempt + 1})" }
            // Something removed the staged generation between the commit and this promotion. Put it
            // back — it is the same device master key under the same new password, so re-staging is
            // not a second rewrap, just a second copy of the file.
            runCatching { keyringRepository.writeNext(username, stagedBytes) }
                .onFailure { KLogger.e(it) { "changeUserPassword: could not re-stage the rewrapped keyring" } }
        }
        return false
    }

    /**
     * Put [previous] back as the stored credential, but only while [committed] — the credential *this*
     * change wrote — is still the one on disk.
     *
     * Unconditional restoration is safe for one flow and unsafe the moment there are two. A second
     * `changeUserPassword` on the same account commits its own credential and promotes its own
     * keyring; if that lands inside this flow's confirmation gap, this flow sees a live keyring that
     * is not its staged one and concludes it failed — which it did — but the credential on disk is now
     * the *rival's*, matching the rival's keyring. Writing [previous] over it strands both changes and
     * the rival's password with them, and it is the only step here that damages an account that was
     * otherwise fine.
     *
     * The compare and the write go through [UserPreferences.replaceCredential] as one primitive: a
     * read-then-upsert here merely narrowed the window, since the rival could commit between this
     * flow's compare and its write. Within one process the primitive closes it; across processes it
     * is advisory, which its KDoc says plainly.
     *
     * @return true only when the credential is demonstrably back on [previous]. A false return is the
     *   signal that the staged keyring generation must be left alone, because it may be the only thing
     *   that opens whatever credential is now on disk.
     */
    private suspend fun restoreCredential(username: String, committed: Password, previous: Password): Boolean =
        runCatching {
            val restored = userPreferences.replaceCredential(username, expected = committed, replacement = previous)
            if (!restored) {
                KLogger.e {
                    "changeUserPassword: the stored credential is no longer the one this change wrote - " +
                        "leaving it alone rather than overwriting another change"
                }
            }
            restored
        }.getOrElse {
            if (it is CancellationException) throw it
            KLogger.e(it) { "changeUserPassword: could not restore the previous credential" }
            false
        }

    /**
     * Complete a password change that was interrupted before its staged keyring was promoted, if
     * [password] is the one it was staged under.
     *
     * Returns null when there is nothing pending, or when the pending generation does not open with
     * this password — in which case it is *not* removed. It may belong to a change made from another
     * device's copy of this account, or to a password the user is about to remember, and deleting it
     * on a failed guess would throw away the only keyring the new password opens.
     */
    private suspend fun resumeStagedKeyring(username: String, password: String): VaultSessionKey? {
        val staged = keyringRepository.readNext(username) ?: return null
        val sessionKey = runCatching { vaultCipher.unlockSession(staged, password) }.getOrElse { failure ->
            KLogger.d { "login: a staged keyring exists for $username but does not open with this password" }
            if (failure is CancellationException) throw failure
            return null
        }
        KLogger.w { "login: completing a password change for $username that was interrupted before promotion" }
        runCatching { keyringRepository.promoteNext(username) }
            .onFailure { KLogger.e(it) { "login: could not promote the staged keyring; it will be retried next login" } }
        return sessionKey
    }

    /** Remove a staged keyring generation that no longer belongs to any pending change. */
    private suspend fun discardStagedKeyring(username: String) {
        runCatching { keyringRepository.deleteNext(username) }
            .onFailure { KLogger.w(it) { "could not remove the staged keyring generation for $username" } }
    }

    /**
     * Decide which password currently opens [username]'s identity store, migrating it onto the
     * derived one when it is still on the login password.
     *
     * The three reachable states and what each returns:
     * - already derived — return it, no write;
     * - on the login password (never migrated, or a previous migration failed) — change it and return
     *   the derived password; if the change fails, log loudly and return the **login** password so the
     *   account stays fully usable and the migration retries on the next login;
     * - neither — a missing or damaged store. Return the derived password; the caller's key
     *   resolution fails either way, and nothing on disk is touched.
     *
     * Never logs either password.
     */
    private suspend fun resolveIdentityStorePassword(
        username: String,
        sessionKey: VaultSessionKey,
        loginPassword: String,
    ): String {
        val derived = vaultCipher.identityStorePassword(sessionKey)
        if (keystoreLifecycle.canOpenKeystore(username, keystoreDir, derived.value)) return derived.value

        if (!keystoreLifecycle.canOpenKeystore(username, keystoreDir, loginPassword)) {
            KLogger.e { "login: identity store for $username opens with neither the derived nor the login password" }
            return derived.value
        }

        KLogger.d { "login: migrating $username's identity store onto the keyring-derived password" }
        val outcome = keystoreLifecycle.changeKeystorePassword(username, keystoreDir, loginPassword, derived)
        if (outcome is Outcome.Error) {
            KLogger.e {
                "login: identity store migration FAILED for $username (${outcome.message}); continuing on the " +
                    "login password, migration will retry on the next login"
            }
            return loginPassword
        }

        if (keystoreLifecycle.canOpenKeystore(username, keystoreDir, derived.value)) {
            KLogger.d { "login: identity store migrated for $username" }
            return derived.value
        }

        // Reported success but did not take. Fall back to whatever still opens the store rather than
        // to whatever the change claimed.
        KLogger.e { "login: identity store migration for $username reported success but did not apply" }
        return if (keystoreLifecycle.canOpenKeystore(username, keystoreDir, loginPassword)) loginPassword else derived.value
    }

    /**
     * Resolve the session RSA key handles. Their second parameter is the *identity-store* password,
     * which since the keyring is the derived value, not the login password. The qualifiers and the
     * parameter shape are frozen — `SyncTlsProvider` and `JvmFingerprintService` resolve the same
     * definitions by qualifier and must keep working untouched.
     *
     * **This is not a proof that [storePassword] opens the store.** Koin's `scoped` definitions cache
     * their first instance for the lifetime of the scope and ignore `parametersOf` on every later
     * resolution, so on a warm scope — a second login without a logout, or anything that already
     * touched these qualifiers — this returns the *previous* login's keys whatever password is passed.
     * Only [KeystoreLifecycle.canOpenKeystore] actually asks the store a question, which is why the
     * migration state machine is built on that call and not on whether this one throws.
     */
    private fun warmIdentityKeys(scope: Scope, username: String, storePassword: String) {
        scope.get<CryptoKey>(named(PUBLIC_ENCRYPTION_KEY_HANDLE)) { parametersOf(username, storePassword) }
        scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) { parametersOf(username, storePassword) }
    }

    /**
     * Once per account, move the identity store off the expensive PKCS#12 parameters it was written
     * with. Best-effort: a failure is logged and login carries on, exactly like [maybeUpgradeKdf].
     *
     * ## Why it is gated on the derived password
     *
     * The cheap parameters are sound *only* because the store's password is 256 bits of HKDF output
     * that nobody can guess. [resolveIdentityStorePassword] returns the **login** password when the
     * store is still un-migrated or when a migration failed, and rewriting that store cheaply would
     * strip the only thing making its password expensive to guess — this app performing a downgrade
     * attack on its own user. So the gate is an equality check against the derived value, and the
     * un-migrated case belongs to `changeKeystorePassword`, which does the same rewrite as part of
     * moving the store onto the derived password in the first place.
     *
     * `IdentityStorePassword` does not replace that check and is not meant to: the type proves where a
     * value came from, and this gate is about which value the **file on disk** is currently sealed
     * with. Holding the derived password says nothing about that. What the type does buy is the line
     * below the gate — the value handed to the writer comes straight out of the derivation rather than
     * out of [storePassword], so the two facts cannot come apart.
     *
     * ## Why it runs after warmIdentityKeys
     *
     * `warmIdentityKeys` resolves the session-scoped `SESSION_IDENTITY_STORE`, i.e. this login's own
     * open of the `.pfx`. Rewriting the file before that would have the session opening a file that
     * is being replaced underneath it. Afterwards, the open store is an in-memory object that owes
     * nothing to the bytes on disk, so the swap cannot disturb it — and a store that failed to open
     * is not one to rewrite.
     */
    private suspend fun maybeReencodeIdentityStore(username: String, sessionKey: VaultSessionKey, storePassword: String) {
        val derived = vaultCipher.identityStorePassword(sessionKey)
        if (storePassword != derived.value) {
            KLogger.w {
                "login: $username's identity store is not on the derived password — leaving its PKCS#12 " +
                    "parameters alone, because they are what protects a guessable password"
            }
            return
        }
        val outcome = runCatching {
            keystoreLifecycle.reencodeIdentityStoreIfLegacy(username, keystoreDir, derived)
        }.getOrElse {
            if (it is CancellationException) throw it
            KLogger.e(it) { "login: identity store re-encode threw for $username (non-fatal)" }
            return
        }
        if (outcome is Outcome.Error) {
            KLogger.e {
                "login: identity store re-encode failed for $username (${outcome.message}); the store is " +
                    "untouched and it will be retried on the next login"
            }
        }
    }

    private fun vaultSession(scope: Scope): VaultSession = scope.get(named(VAULT_SESSION_HANDLE))

    /**
     * Undo a failed signup: zero the master key, delete the keyring and the identity store — and,
     * when [deleteDatabase], the vault database this bootstrap created — then close the session
     * scope so a retry cannot resolve the abandoned account's cached RSA keys.
     *
     * [deleteDatabase] is set by the caller only after its own successful [initDatabase], never
     * because a database merely exists: a vault that predates this signup (a restore drill, a
     * partially deleted account) must survive the rollback untouched.
     */
    private suspend fun rollbackAccount(scope: Scope, username: String, sessionKey: VaultSessionKey, deleteDatabase: Boolean) {
        KLogger.w { "signup: rolling back the partially created account for $username" }
        runCatching { sessionKey.destroy() }
        runCatching { keyringRepository.delete(username) }
            .onFailure { KLogger.e(it) { "signup rollback: could not delete the keyring" } }
        runCatching { keystoreLifecycle.deleteKeystoreForUser(username, keystoreDir) }
            .onFailure { KLogger.e(it) { "signup rollback: could not delete the identity store" } }
        if (deleteDatabase) {
            runCatching { storage.delete(username) }
                .onFailure { KLogger.e(it) { "signup rollback: could not delete the vault database" } }
        }
        runCatching { scope.close() }
    }

    private fun initDatabase(username: String, sessionKey: VaultSessionKey): Failure? {
        if (storage.exists(username)) {
            return AuthFailure.AccountAlreadyExists
        }
        return runCatching {
            storage.create(
                username,
                portableVaultFormat?.seal(username, ByteArray(0), sessionKey)
                    ?: vaultCipher.encryptVault(ByteArray(0), sessionKey),
            )
            null
        }.getOrElse {
            KLogger.e(it) { "failed to init db" }
            AuthFailure.SignupFailure
        }
    }

    private fun buildLoggedInUser(username: String, password: String): AppUser.LoggedIn =
        AppUser.LoggedIn(userName = username, password = hashPassword(password))

    /** Derive a fresh credential for [password] with the current target KDF (Argon2id). */
    private fun hashPassword(password: String): Password {
        val params = KdfParams.ARGON2ID_DEFAULT
        val salt = secureRandom.nextBytes(SALT_BYTES)
        val hash = passwordHasher.derive(password, salt, params)
        return Password(hash = encodeBase64(hash), salt = encodeBase64(salt), kdf = params)
    }

    /** Verify [password] against [stored] using the params it was derived under (null = legacy PBKDF2). */
    private fun verifyPassword(stored: Password, password: String): Boolean {
        if (stored.hash.isBlank() || stored.salt.isBlank()) return false // corrupt record never verifies
        val params = stored.kdf ?: KdfParams.LEGACY_PBKDF2
        val derived = passwordHasher.derive(password, decodeBase64(stored.salt), params)
        return constantTimeEquals(derived, decodeBase64(stored.hash))
    }

    // Constant-time comparison: examines every byte regardless of where a mismatch occurs, so
    // response timing can't leak how much of the stored hash a guess matched.
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.isEmpty() || a.size != b.size) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
        return diff == 0
    }

    /**
     * If [stored] wasn't produced with the current target KDF, re-derive [password] under it and
     * persist the upgraded credential. Best-effort — a failure is logged and never blocks login.
     *
     * Returns the credential the caller must hand out. `LoginUser` upserts whatever login returns,
     * so returning [stored] after a successful upgrade writes the legacy record straight back over
     * it and the upgrade re-fires on every login, forever — at the legacy KDF's full verification
     * cost each time.
     */
    private suspend fun maybeUpgradeKdf(username: String, password: String, stored: Password): Password {
        if ((stored.kdf ?: KdfParams.LEGACY_PBKDF2) == KdfParams.ARGON2ID_DEFAULT) return stored
        return runCatching {
            val upgraded = hashPassword(password)
            userPreferences.upsert(AppUser.LoggedIn(userName = username, password = upgraded))
            KLogger.d { "login: upgraded KDF to argon2id for $username" }
            upgraded
        }.getOrElse {
            KLogger.e(it) { "login: KDF upgrade failed (non-fatal)" }
            stored
        }
    }

    // Legacy Android writes used android.util.Base64.DEFAULT, which wraps every 76 chars with
    // a trailing newline. Use Mime decode (lenient) so legacy and new credentials both round-trip.
    private fun decodeBase64(input: String): ByteArray = Base64.Mime.decode(input)

    private fun encodeBase64(input: ByteArray): String = Base64.Mime.encode(input)
}
