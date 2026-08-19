package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.exception.KeystoreFailure
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.repository.KeystorePreferences
import ai.passman.domain.keystore.repository.KeystoreRepository
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.repository.PasswordRepository
import ai.passman.domain.user.GeneratePassword
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Provisions the account's starter keystore, once: `passman-keystore.pfx` with one RSA key under
 * alias `main`, sealed with a generated random password that is saved as the vault entry
 * "passman keystore". Invoked from the login/signup success hooks (never inside the account
 * bootstrap's rollback contract) and non-fatal to them.
 *
 * The password is random rather than anything account-derived for the same reason the PGP ring
 * passphrase is: PKCS#12 PBE is orders of magnitude cheaper to brute-force offline than the
 * Argon2id login KDF, and the file is designed to leave the device — a cracked keystore must not
 * yield anything but itself. The user reads the password out of the vault entry when a screen asks
 * for it.
 *
 * ## Guards, and why every "already have" answer sets the flag
 *
 * Creation happens only when the account has zero visible keystores AND no "passman keystore"
 * vault entry AND the per-account [KeystorePreferences] flag is unset. The first two guards do not
 * just skip — they SET the flag, so the decision "this account has its keystore story settled" is
 * made exactly once per device. That is what makes deletion final: once the flag is set, a user
 * who deletes the starter keystore (or its entry) never has it silently resurrected, including
 * when the artifact originally arrived by sync rather than local creation. One deliberate
 * exception: a vault that cannot be READ ([PasswordRepository.listPasswordEntries] error) answers
 * nothing — provisioning would risk duplicating an entry the unreadable vault already holds, so
 * the attempt aborts with the flag untouched and the next login retries.
 *
 * ## The commit sequence is non-cancellable
 *
 * Everything past the guards — create keystore, record its password, set the flag, roll back on
 * failure — runs under [NonCancellable]. The callers cap this use case with `withTimeoutOrNull`,
 * and that cap must only ever bound the cheap cancellable guard phase: a cancellation delivered
 * after the blocking keystore write landed on disk but before the vault entry recorded its
 * password would skip both the record and the rollback, leaving an artifact whose password died
 * with the coroutine — and the guards would then see "a keystore exists" and flag the account,
 * making the orphan permanent. So once committed, a slow keygen simply runs to completion (a slow
 * first login, not a destroyed default), and the caller's cancellation surfaces after the block
 * finishes.
 *
 * Ordering within the sequence: keystore FIRST, vault entry second (retried once); if the entry
 * cannot be written the keystore is deleted again, because a keystore whose password was never
 * recorded anywhere is unrecoverable — worse than no keystore. If keystore creation fails,
 * nothing is written at all.
 *
 * Two-device race: both devices signing up before their first sync yields two starter keystores
 * and two identically-named entries; sync's usual filename last-write-wins keeps one file, and
 * the entry whose password opens it is the survivor. Documented and accepted for v1.
 *
 * Success value: `true` when the keystore was created on this call, `false` for every skip.
 */
class EnsureDefaultKeystore(
    private val keystoreRepository: KeystoreRepository,
    private val passwordRepository: PasswordRepository,
    private val keystorePreferences: KeystorePreferences,
    private val userPreferences: UserPreferences,
    private val generatePassword: GeneratePassword,
    private val createKeyStore: CreateKeyStore,
    private val deleteKeystore: DeleteKeystore,
    private val addPassword: AddPassword,
) : Usecase<Unit, Outcome<Boolean>> {

    override suspend fun invoke(param: Unit): Outcome<Boolean> {
        val user = userPreferences.getUser() as? AppUser.LoggedIn
            ?: return Outcome.Error("not signed in", KeystoreFailure.CreateKeystore)
        if (keystorePreferences.isDefaultKeystoreCreated(user.userName)) return Outcome.Success(false)

        if (keystoreRepository.getAllKeystores().isNotEmpty()) {
            // Settled without creating — see the class KDoc for why this makes deletion final.
            keystorePreferences.setDefaultKeystoreCreated(user.userName)
            return Outcome.Success(false)
        }
        val entries = when (val listed = passwordRepository.listPasswordEntries()) {
            // Cannot tell "empty vault" from "unreadable vault" — do NOT provision and do NOT
            // set the flag; the next login retries against a hopefully readable vault.
            is Outcome.Error -> return listed
            is Outcome.Success -> listed.value
        }
        if (entries.any { it.entryName in knownEntryNames(user.userName) }) {
            keystorePreferences.setDefaultKeystoreCreated(user.userName)
            return Outcome.Success(false)
        }

        // Committed. See the class KDoc: from here the sequence must not be torn apart by the
        // caller's timeout or cancellation.
        return withContext(NonCancellable) { provision(user.userName) }
    }

    private suspend fun provision(userName: String): Outcome<Boolean> {
        val storePassword = generatePassword(GeneratePassword.PROVISIONED_SECRET)
        val created = createKeyStore(
            CreateKeyStore.CreateRequest(
                keystoreName = KEYSTORE_NAME,
                keystorePassword = storePassword,
                keyAlgorithm = KeystoreKeyAlgorithm.RSA, // the CreateKeyStore screen's default
                keyAlias = KEY_ALIAS,
                aliasPassword = storePassword, // one password to look up, not two
                keystoreType = KeyStoreType.PKCS12,
            ),
        )
        val info = when (created) {
            is Outcome.Error -> return created
            is Outcome.Success -> created.value
        }

        var entrySaved = false
        try {
            entrySaved = addPassword(entry(userName, storePassword))
            // One retry (matching EnsureDefaultPgpRings): giving up costs the keystore, which is
            // worth a second plain vault write.
            if (!entrySaved) entrySaved = addPassword(entry(userName, storePassword))
        } finally {
            // A keystore whose password nobody recorded is unrecoverable — remove it. The
            // finally also covers addPassword throwing; cancellation cannot reach here (the
            // whole sequence is NonCancellable).
            if (!entrySaved) {
                deleteKeystore(
                    DeleteKeystore.DeleteKeystoreRequest(
                        keystorePath = info.path,
                        keystoreName = info.name,
                        keystorePassword = storePassword,
                    ),
                )
            }
        }
        if (!entrySaved) {
            return Outcome.Error("could not record the starter keystore password", KeystoreFailure.CreateKeystore)
        }

        keystorePreferences.setDefaultKeystoreCreated(userName)
        return Outcome.Success(true)
    }

    private fun entry(userName: String, storePassword: String) = AddPassword.EntryData(
        entryName = entryName(userName),
        // The username field names the artifact the password opens.
        userName = STORE_FILE_NAME,
        password = storePassword,
        website = "",
        notes = "Created automatically when this profile was set up on this device. This is the " +
            "password for the starter keystore '$STORE_FILE_NAME' and its key '$KEY_ALIAS'.",
    )

    companion object {
        /** Saved as `passman-keystore.pfx`; the extensionless name is what [CreateKeyStore] takes. */
        const val KEYSTORE_NAME = "passman-keystore"
        const val STORE_FILE_NAME = "$KEYSTORE_NAME.pfx"

        /**
         * NOT `passmanMain` — `KeyStoreDetailsContent` hides the Delete action when an alias by
         * that name exists, and the starter keystore must stay deletable.
         */
        const val KEY_ALIAS = "main"

        /** The vault entry holding the generated keystore password. */
        const val ENTRY_NAME = "passman keystore"

        /** The vault entry name carries the profile so it reads unambiguously in any listing. */
        fun entryName(userName: String) = "$userName $ENTRY_NAME"

        /**
         * Every spelling this use-case has ever written, oldest last — the guard must recognise
         * all of them or an account created on an earlier build re-provisions a duplicate.
         */
        fun knownEntryNames(userName: String) =
            setOf(entryName(userName), "$ENTRY_NAME ($userName)", ENTRY_NAME)
    }
}
