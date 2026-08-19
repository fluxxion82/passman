package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.repository.PasswordRepository
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpPreferences
import ai.passman.domain.pgp.repository.PgpRepository
import ai.passman.domain.user.GeneratePassword
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Keeps the account's default PGP rings paired with the vault entry ("passman pgp") that records
 * their passphrase. Two entry points, both non-fatal to the login/signup that invokes them:
 *
 * - [Request.RecordFreshRings]: signup created the rings inside `bootstrapAccount` (before the
 *   vault session bound, so the entry could not be written there); the passphrase was generated in
 *   signup scope and is recorded here, after success. If the vault refuses the entry — retried
 *   once — the seconds-old rings are DELETED: a ring whose passphrase nobody holds is
 *   unrecoverable, and an orphaned unknowable passphrase is strictly worse than re-provisioning.
 *   The next login rebuilds through [Request.EnsureProvisioned].
 * - [Request.EnsureProvisioned]: the login-side (and bio-signup-side) guard. Provisions rings +
 *   entry only for an account that has NO secret keys (public-only keys such as the auto-imported
 *   developer key don't count), NO "passman pgp" entry and an unset per-account flag. Accounts
 *   that predate the passphrase decoupling keep their login-password rings untouched (the explicit
 *   PGP change-password screen is their migration path), and the flag-once semantics make a
 *   deliberate key deletion final — nothing resurrects it, including artifacts that arrived by
 *   sync. Two guard answers deliberately do NOT set the flag: an unreadable vault
 *   ([PasswordRepository.listPasswordEntries] error — provisioning would risk duplicating an entry
 *   the vault already holds, so retry next login), while an occupied default-ring slot
 *   ([PgpFailure.DefaultRingsOccupied] — a permanent condition) DOES set it, or every login would
 *   re-fail forever.
 *
 * ## The commit sequence is non-cancellable
 *
 * Everything past the guards — create rings, record the passphrase, set the flag, roll back on
 * failure — runs under [NonCancellable] (the RecordFreshRings path in its entirety). The callers
 * cap this use case with `withTimeoutOrNull`, and that cap must only ever bound the cheap
 * cancellable guard phase: a cancellation delivered after the blocking keygen landed on disk but
 * before the entry recorded the passphrase would skip both the record and the rollback, and the
 * secret-keys guard would then flag the account, making the orphan permanent. So once committed, a
 * slow 4096-bit keygen simply runs to completion (a slow first login, not a destroyed default),
 * and the caller's cancellation surfaces after the block finishes.
 *
 * Residual risk, accepted: a process death in the seconds between signup success and the entry
 * write leaves rings whose passphrase died with the process. The next login cannot tell those from
 * a legacy account's rings (or from rings whose passphrase the user changed deliberately), so it
 * flags-and-leaves rather than guessing — deleting real key material on a wrong guess is the worse
 * failure. The user's remedy is deleting the unusable key and creating one on the PGP screen.
 *
 * Success value: `true` when something was provisioned or recorded on this call, `false` for every
 * skip.
 */
class EnsureDefaultPgpRings(
    private val pgpRepository: PgpRepository,
    private val pgpPreferences: PgpPreferences,
    private val passwordRepository: PasswordRepository,
    private val userPreferences: UserPreferences,
    private val generatePassword: GeneratePassword,
    private val addPassword: AddPassword,
    private val pgpEventPersistence: PgpEventPersistence,
) : Usecase<EnsureDefaultPgpRings.Request, Outcome<Boolean>> {

    sealed class Request {
        /**
         * Signup just created the default rings sealed with [passphrase]; record it as the vault
         * entry (or roll the rings back if that proves impossible).
         */
        data class RecordFreshRings(val passphrase: String) : Request()

        /** Login-side: provision default rings for an account that has nothing. */
        data object EnsureProvisioned : Request()
    }

    override suspend fun invoke(param: Request): Outcome<Boolean> {
        val user = userPreferences.getUser() as? AppUser.LoggedIn
            ?: return Outcome.Error("not signed in", PgpFailure.GeneralPgpError("not signed in"))
        return when (param) {
            // The rings already exist; the record (and its rollback-on-failure) is the whole
            // commit sequence, so all of it is shielded from the caller's timeout.
            is Request.RecordFreshRings -> withContext(NonCancellable) { record(user.userName, param.passphrase) }
            Request.EnsureProvisioned -> ensure(user.userName)
        }
    }

    private suspend fun ensure(userName: String): Outcome<Boolean> {
        if (pgpPreferences.isDefaultRingsProvisioned(userName)) return Outcome.Success(false)

        // Existing SECRET keys (legacy login-password rings, synced or imported keypairs) and an
        // existing entry both settle the question WITHOUT creating anything: this must never
        // overwrite key material, and a deliberate deletion stays deleted. Public-only keys do
        // not count — the auto-imported developer key is one, and treating it as "this account
        // has keys" would permanently block provisioning for every account that carries it.
        if (pgpRepository.getKeys().any { it.secretKey != null }) {
            pgpPreferences.setDefaultRingsProvisioned(userName)
            return Outcome.Success(false)
        }
        val entries = when (val listed = passwordRepository.listPasswordEntries()) {
            // Cannot tell "empty vault" from "unreadable vault" — do NOT provision and do NOT
            // set the flag; the next login retries against a hopefully readable vault.
            is Outcome.Error -> return listed
            is Outcome.Success -> listed.value
        }
        if (entries.any { it.entryName in knownEntryNames(userName) }) {
            pgpPreferences.setDefaultRingsProvisioned(userName)
            return Outcome.Success(false)
        }

        // Committed. See the class KDoc: from here the sequence must not be torn apart by the
        // caller's timeout or cancellation.
        return withContext(NonCancellable) {
            val passphrase = generatePassword(GeneratePassword.PROVISIONED_SECRET)
            when (val created = pgpRepository.createDefaultKeyRings(passphrase)) {
                is Outcome.Error -> {
                    if (created.cause == PgpFailure.DefaultRingsOccupied) {
                        // Something (e.g. a public-only default ring that arrived alone by sync)
                        // occupies a default-ring name that the secret-keys guard cannot see.
                        // Permanent — flag the account settled, or every login re-fails here.
                        pgpPreferences.setDefaultRingsProvisioned(userName)
                        return@withContext Outcome.Success(false)
                    }
                    return@withContext created
                }
                is Outcome.Success -> pgpEventPersistence.update(PgpEvent.KeyCreated)
            }
            record(userName, passphrase)
        }
    }

    /** Precondition: the caller already runs this under [NonCancellable]. */
    private suspend fun record(userName: String, passphrase: String): Outcome<Boolean> {
        var saved = false
        try {
            saved = addPassword(entry(userName, passphrase))
            // One retry: giving up costs the rings, which is worth a second plain vault write.
            if (!saved) saved = addPassword(entry(userName, passphrase))
        } finally {
            // See the class KDoc: an unrecorded passphrase is unrecoverable, so the fresh rings
            // must go. The finally also covers addPassword throwing; cancellation cannot reach
            // here (the whole sequence is NonCancellable).
            if (!saved) {
                pgpRepository.deleteDefaultKeyRings()
                pgpEventPersistence.update(PgpEvent.KeyModified)
            }
        }
        if (!saved) {
            return Outcome.Error(
                "could not record the PGP ring passphrase",
                PgpFailure.GeneralPgpError("vault write failed"),
            )
        }
        pgpPreferences.setDefaultRingsProvisioned(userName)
        return Outcome.Success(true)
    }

    private fun entry(userName: String, passphrase: String) = AddPassword.EntryData(
        entryName = entryName(userName),
        // The username field names the artifact the passphrase opens.
        userName = RINGS_LABEL,
        password = passphrase,
        website = "",
        notes = "Created automatically when this profile was set up on this device. This is the " +
            "passphrase for the profile's default PGP key rings.",
    )

    companion object {
        /** The vault entry holding the generated ring passphrase. */
        const val ENTRY_NAME = "passman pgp"

        /** What the entry's username field shows — the artifact the passphrase opens. */
        const val RINGS_LABEL = "passman key rings"

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
