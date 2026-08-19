package ai.passman.domain.user.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.models.AppUser

@Suppress("TooManyFunctions")
interface UserRepository {
    /**
     * [pgpPassphrase] seals the default PGP key rings created as part of the new account. It is
     * deliberately NOT the login password: PGP S2K is orders of magnitude cheaper to brute-force
     * offline than the Argon2id login KDF, and the ring files are designed to leave the device
     * (sync, share, export) — a cracked ring file must not yield the vault login. The caller
     * ([ai.passman.domain.user.SignUpUser]) generates it and records it as a vault entry after the
     * signup succeeds; accounts created before this decoupling keep login-password rings and
     * migrate through the explicit PGP change-password screen.
     */
    suspend fun signup(username: String, password: String, pgpPassphrase: String): Outcome<AppUser>
    suspend fun login(username: String, password: String): Outcome<AppUser>
    suspend fun bioLogin(username: String, password: String): Outcome<AppUser>
    suspend fun bioSignup(username: String, password: String): Outcome<AppUser>
    suspend fun changeUserPassword(oldPassword: String, newPassword: String): Outcome<AppUser>

    suspend fun logout()
}
