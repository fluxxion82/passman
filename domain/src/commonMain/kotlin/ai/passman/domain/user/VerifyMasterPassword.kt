package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository

/**
 * Re-authenticates the person already using the app, before an action that hands out key material.
 *
 * The master password rather than an artifact's own passphrase, deliberately: a displaced copy may
 * be a foreign ring, a keystore, or unparseable, so its passphrase is a secret the user may not have
 * — gating on it would lock people out of rescuing exactly the files they most need. The master
 * password is one they always know, so it adds real friction without ever making recovery impossible.
 */
class VerifyMasterPassword(
    private val userRepository: UserRepository,
    private val userPreferences: UserPreferences,
) : Usecase<String, Boolean> {
    override suspend fun invoke(param: String): Boolean {
        if (param.isEmpty()) return false
        val user = userPreferences.getUser() as? AppUser.LoggedIn ?: return false
        return userRepository.verifyMasterPassword(user.userName, param)
    }
}
