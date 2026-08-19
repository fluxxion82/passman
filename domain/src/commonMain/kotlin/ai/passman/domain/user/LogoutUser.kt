package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.crypto.repository.CryptoPreferences
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.UserEvent
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.domain.user.repository.UserRepository

class LogoutUser(
    private val userPreferences: UserPreferences,
    private val cryptoPreferences: CryptoPreferences,
    private val userRepository: UserRepository,
    private val userEvents: UserEventPersistence,
) : Usecase<Boolean, Unit> {

    override suspend fun invoke(param: Boolean) {
        userEvents.update(UserEvent.LoginChanged(AppUser.Anonymous))
        userRepository.logout()

        // only clears session id since we save credentials here
        // and we need those to log in
        userPreferences.clear()

        // Full logout
        if (param) {
            // we might want two different clear options for full and partial clearing
            cryptoPreferences.clearKeys()
        }
    }
}
