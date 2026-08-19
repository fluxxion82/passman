package ai.passman.domain.user

import ai.passman.domain.base.invoke
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.runBlocking

class GetKnownUsernamesTest {

    @Test
    fun `returns the preferences usernames verbatim`() = runBlocking {
        val usernames = listOf("mia", "ada", "zoe")
        val useCase = GetKnownUsernames(FakeUserPreferences(usernames))

        assertEquals(usernames, useCase())
    }
}

private class FakeUserPreferences(
    private val usernames: List<String>,
) : UserPreferences {
    override suspend fun getUser(): AppUser = unsupported()
    override suspend fun upsert(user: AppUser) = unsupported()
    override suspend fun getStoredCredentials(username: String): Password? = unsupported()
    override suspend fun getKnownUsernames(): List<String> = usernames
    override suspend fun getUserState(): UserState? = unsupported()
    override suspend fun setUserState(state: UserState) = unsupported()
    override suspend fun getSessionId(): String = unsupported()
    override suspend fun clear() = unsupported()

    private fun unsupported(): Nothing = throw UnsupportedOperationException("not used by this test")
}
