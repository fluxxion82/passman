package ai.passman.domain.user.repository

import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password

interface UserPreferences {
    suspend fun getUser(): AppUser
    suspend fun upsert(user: AppUser)
    suspend fun getStoredCredentials(username: String): Password?

    /**
     * Usernames of every account that has logged in on this device, last-used first, the rest
     * alphabetical. Readable before login by design — the login screen offers these as
     * suggestions. Pre-auth account disclosure is a deliberate, recorded decision.
     */
    suspend fun getKnownUsernames(): List<String> = emptyList()

    /**
     * Replace [username]'s stored credential with [replacement] — but only while the credential on
     * disk is still [expected].
     *
     * This exists for the password-change rollback: restoring the *previous* credential is safe for
     * one change and unsafe the moment there are two, because a rival change that committed inside
     * the gap owns the stored credential, and writing over it strands the rival's keyring with a
     * password nothing on disk matches. A bare read-compare-upsert narrows that window without
     * closing it, so the compare and the write are one primitive here.
     *
     * This default is that bare read-compare-upsert — correct semantics, unguarded window — so
     * in-memory fakes get the behaviour for free. Real implementations override it to make the
     * compare-and-write atomic *within the process*; across processes it stays advisory, because the
     * underlying settings stores offer no compare-and-set.
     *
     * @return true only when [replacement] was written. False means the stored credential was not
     * [expected] (or does not exist) and nothing was changed.
     */
    suspend fun replaceCredential(username: String, expected: Password, replacement: Password): Boolean {
        if (getStoredCredentials(username) != expected) return false
        upsert(AppUser.LoggedIn(username, replacement))
        return true
    }
    suspend fun getUserState(): UserState?
    suspend fun setUserState(state: UserState)
    suspend fun getSessionId(): String

    suspend fun clear()
}
