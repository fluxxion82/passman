package ai.passman.domain.user.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.models.AppUser

@Suppress("TooManyFunctions")
interface UserRepository {
    /**
     * Creates the account and nothing else the user did not ask for: the device keyring, the
     * identity store and an empty vault. No PGP rings, no starter keystore — every device would
     * mint its own under the same fixed filenames, and the first sync between two of them would
     * overwrite one device's secret ring with the other's. Keys and keystores are created on the
     * Create screens, and a second device inherits the first device's by syncing.
     */
    suspend fun signup(username: String, password: String): Outcome<AppUser>
    suspend fun login(username: String, password: String): Outcome<AppUser>

    /**
     * Sign in with no typed password at all: the master password is recovered from the account's
     * biometric enrolment and then run through [login] unchanged.
     *
     * There is no password parameter on purpose. The previous shape took one and required it, which
     * made this "password AND fingerprint" — a second factor bolted onto a login that already
     * worked, not the passwordless unlock the button promised. Anything downstream of the recovery
     * is the ordinary login path, so the blast radius of the whole feature is the wrapping.
     */
    suspend fun bioLogin(username: String): Outcome<AppUser>
    suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser>

    /**
     * Is [password] the account's master password? Checks and nothing else — no session, no
     * upgrade, no state change.
     *
     * For re-authenticating before a sensitive action inside an already-unlocked app. [login] would
     * work as a check but does far more than check, and reusing it for the question "is this the
     * right password" would tie a confirmation prompt to session setup.
     */
    suspend fun verifyMasterPassword(username: String, password: String): Boolean

    suspend fun logout()
}
