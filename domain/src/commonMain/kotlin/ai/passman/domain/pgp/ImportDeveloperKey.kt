package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.pgp.repository.PgpRepository

/**
 * Installs the developer public key bundled with the app so the user can encrypt to / verify
 * signatures from the developer.
 *
 * [Mode.OncePerAccount] is the auto-import hook ([ai.passman.domain.user.LoginUser] /
 * [ai.passman.domain.user.SignUpUser] call it after a successful login or signup): it runs at
 * most once per account and device, and a user who deletes the key afterwards keeps it deleted
 * on that device (the file syncs between paired devices; the flag does not — see
 * [PgpRepository.importBundledDeveloperKey] for the exact scope). [Mode.Force] is the explicit
 * "Import developer key" menu action and re-imports past the flag — still fingerprint-verified
 * and occupant-guarded by the repository.
 *
 * Success value: `true` when the key was (re)imported, `false` for the already-ran skip.
 */
class ImportDeveloperKey(
    private val pgpRepository: PgpRepository,
    private val pgpEventPersistence: PgpEventPersistence,
) : Usecase<ImportDeveloperKey.Mode, Outcome<Boolean>> {

    enum class Mode { OncePerAccount, Force }

    override suspend fun invoke(param: Mode): Outcome<Boolean> {
        val outcome = pgpRepository.importBundledDeveloperKey(force = param == Mode.Force)
        if (outcome is Outcome.Success && outcome.value) {
            // Same refresh signal ImportPgpKey emits, so an open key list picks the key up.
            pgpEventPersistence.update(PgpEvent.KeyCreated)
        }
        return outcome
    }
}
