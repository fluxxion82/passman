package ai.passman.domain.user

import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences

/**
 * Minimal [UserPreferences] fake: a fixed [user] — by default a logged-in account, or any
 * [AppUser] (e.g. [AppUser.Anonymous] for the not-signed-in branches); everything else fails
 * loudly.
 */
class FakeLoggedInUserPreferences(private val user: AppUser) : UserPreferences {
    constructor(userName: String = "alice") : this(AppUser.LoggedIn(userName, Password("hash", "salt")))

    override suspend fun getUser(): AppUser = user

    override suspend fun upsert(user: AppUser): Unit = unsupported("upsert")
    override suspend fun getStoredCredentials(username: String): Password? = unsupported("getStoredCredentials")
    override suspend fun getUserState(): UserState? = unsupported("getUserState")
    override suspend fun setUserState(state: UserState): Unit = unsupported("setUserState")
    override suspend fun getSessionId(): String = unsupported("getSessionId")
    override suspend fun clear(): Unit = unsupported("clear")

    companion object {
        private fun unsupported(name: String): Nothing =
            throw UnsupportedOperationException("FakeLoggedInUserPreferences.$name was not configured for this test")
    }
}
