package ai.passman.domain.user

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.domain.user.repository.BiometricUnlockRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * The two rules the use cases add on top of the repository, both about *which account* is being
 * talked about.
 *
 * They exist because the two callers disagree: the login screen is asking about a name being typed
 * by somebody who is not signed in, and settings is asking about the session it lives in. Getting
 * that wrong is not a cosmetic bug — enrolling stores a copy of a master password, and enrolling
 * against the wrong name seals one account's password under another account's key.
 */
class BiometricUnlockUseCaseTest {

    @Test
    fun `the login screen asks about the name in the field, not the last signed-in account`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("ada"))
        val useCase = GetBiometricUnlockState(repository, FakeLoggedInUserPreferences("mia"))

        assertTrue(useCase(GetBiometricUnlockState.Request.ForUsername("ada")).canUnlock)
        assertFalse(useCase(GetBiometricUnlockState.Request.ForUsername("mia")).canUnlock)
    }

    @Test
    fun `settings asks about the signed-in account`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("mia"))
        val useCase = GetBiometricUnlockState(repository, FakeLoggedInUserPreferences("mia"))

        assertTrue(useCase(GetBiometricUnlockState.Request.ForSignedInUser).canUnlock)
    }

    /**
     * A blank field must not reach the platform. Asking about "" would answer with the *device's*
     * availability and light the login button up before anything has been typed.
     */
    @Test
    fun `a blank username is answered without consulting the platform`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("mia"))
        val useCase = GetBiometricUnlockState(repository, FakeLoggedInUserPreferences("mia"))

        val state = useCase(GetBiometricUnlockState.Request.ForUsername("   "))

        assertEquals(BiometricUnlockState.Unsupported, state)
        assertTrue(repository.queried.isEmpty())
    }

    @Test
    fun `usernames are trimmed the same way the login path trims them`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("mia"))
        val useCase = GetBiometricUnlockState(repository, FakeLoggedInUserPreferences("mia"))

        assertTrue(useCase(GetBiometricUnlockState.Request.ForUsername("  mia  ")).canUnlock)
    }

    /**
     * The account is resolved inside the use case, never handed in. Anything else is one typo away
     * from wrapping the signed-in user's password under a different account's key.
     */
    @Test
    fun `enabling enrols the signed-in account`() = runTest {
        val repository = FakeBiometricUnlockRepository()
        val useCase = SetBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

        assertIs<Outcome.Success<Unit>>(useCase(SetBiometricUnlock.Request.Enable("master")))

        assertEquals(listOf("mia" to "master"), repository.enabled)
    }

    @Test
    fun `enabling with nobody signed in is refused before any prompt`() = runTest {
        val repository = FakeBiometricUnlockRepository()
        val useCase = SetBiometricUnlock(repository, FakeLoggedInUserPreferences(AppUser.Anonymous))

        val outcome = useCase(SetBiometricUnlock.Request.Enable("master"))

        assertIs<Outcome.Error>(outcome)
        assertTrue(repository.enabled.isEmpty())
    }

    @Test
    fun `disabling removes the signed-in account's enrolment`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("mia"))
        val useCase = SetBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

        assertIs<Outcome.Success<Unit>>(useCase(SetBiometricUnlock.Request.Disable))

        assertEquals(listOf("mia"), repository.disabled)
    }
}

private class FakeBiometricUnlockRepository(
    private val enrolled: Set<String> = emptySet(),
    private val availability: BiometricAvailability = BiometricAvailability.Available,
) : BiometricUnlockRepository {
    val queried = mutableListOf<String>()
    val enabled = mutableListOf<Pair<String, String>>()
    val disabled = mutableListOf<String>()

    override suspend fun biometricUnlockState(username: String): BiometricUnlockState {
        queried += username
        return BiometricUnlockState(availability = availability, enrolled = username in enrolled)
    }

    override suspend fun enable(username: String, password: String): Outcome<Unit> {
        enabled += username to password
        return Outcome.Success(Unit)
    }

    override suspend fun disable(username: String) {
        disabled += username
    }
}
