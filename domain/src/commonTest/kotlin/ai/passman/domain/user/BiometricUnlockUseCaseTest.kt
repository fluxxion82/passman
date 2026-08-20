package ai.passman.domain.user

import ai.passman.domain.base.invoke
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

    // ------------------------------------------------- the one-time enrolment offer

    /**
     * The rule the whole flag exists for. Asking once is a feature nobody knew about becoming
     * discoverable; asking every login is the app arguing with a user who has already said no.
     */
    @Test
    fun `the offer is made once and spends itself`() = runTest {
        val repository = FakeBiometricUnlockRepository()
        val useCase = OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

        assertTrue(useCase())
        assertEquals(setOf("mia"), repository.offered, "deciding to ask has to record the ask")
        assertFalse(useCase(), "a second login must not ask again")
    }

    /** One question per account, not per device: a second account on the phone still gets asked. */
    @Test
    fun `spending one account's offer leaves another account's alone`() = runTest {
        val repository = FakeBiometricUnlockRepository()

        assertTrue(OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))())
        assertTrue(OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("ada"))())
    }

    @Test
    fun `an account that is already enrolled is not offered`() = runTest {
        val repository = FakeBiometricUnlockRepository(enrolled = setOf("mia"))
        val useCase = OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

        assertFalse(useCase())
        assertTrue(repository.offered.isEmpty(), "an offer that was never made must not be spent")
    }

    /**
     * Desktop reports [BiometricAvailability.NoHardware], so this is also the assertion that the
     * dialog can never appear there.
     */
    @Test
    fun `a device that cannot authenticate is never offered`() = runTest {
        BiometricAvailability.entries.filter { it != BiometricAvailability.Available }.forEach { availability ->
            val repository = FakeBiometricUnlockRepository(availability = availability)
            val useCase = OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

            assertFalse(useCase(), "$availability must not raise the offer")
            assertTrue(repository.offered.isEmpty(), "$availability must not spend the offer")
        }
    }

    @Test
    fun `nobody signed in is never offered`() = runTest {
        val repository = FakeBiometricUnlockRepository()
        val useCase = OfferBiometricUnlock(repository, FakeLoggedInUserPreferences(AppUser.Anonymous))

        assertFalse(useCase())
        assertTrue(repository.queried.isEmpty(), "there is no account to ask about")
    }

    /**
     * A flag that did not persist cannot stop the next login asking again, so the offer is dropped
     * rather than shown. The user can still find the setting; they cannot un-see a prompt that
     * returns every time they sign in.
     */
    @Test
    fun `an offer that cannot be recorded is not made`() = runTest {
        val repository = FakeBiometricUnlockRepository().apply {
            recordFailure = IllegalStateException("preferences unwritable")
        }
        val useCase = OfferBiometricUnlock(repository, FakeLoggedInUserPreferences("mia"))

        assertFalse(useCase())
    }

    /**
     * The signup form asks its own question, so it spends the offer without making one. Without
     * this, an account that ticked nothing on the form is asked the same thing again — as a modal —
     * at its very next login.
     */
    @Test
    fun `recording an offer directly stops the dialog ever being raised`() = runTest {
        val repository = FakeBiometricUnlockRepository()
        val preferences = FakeLoggedInUserPreferences("mia")

        RecordBiometricUnlockOffered(repository, preferences)(Unit)

        assertEquals(setOf("mia"), repository.offered)
        assertFalse(OfferBiometricUnlock(repository, preferences)())
    }

    @Test
    fun `recording an offer with nobody signed in touches nothing`() = runTest {
        val repository = FakeBiometricUnlockRepository()

        RecordBiometricUnlockOffered(repository, FakeLoggedInUserPreferences(AppUser.Anonymous))(Unit)

        assertTrue(repository.offered.isEmpty())
    }

    /**
     * The signup form's question: what can this device do, with no account to ask about. It has to
     * reach the platform without a username, which [GetBiometricUnlockState] deliberately refuses.
     */
    @Test
    fun `device availability is answered without an account`() = runTest {
        BiometricAvailability.entries.forEach { availability ->
            val repository = FakeBiometricUnlockRepository(availability = availability)

            assertEquals(availability, GetBiometricAvailability(repository)())
            assertTrue(repository.queried.isEmpty(), "no account was named, so none may be looked up")
        }
    }
}

private class FakeBiometricUnlockRepository(
    private val enrolled: Set<String> = emptySet(),
    private val availability: BiometricAvailability = BiometricAvailability.Available,
    val offered: MutableSet<String> = mutableSetOf(),
) : BiometricUnlockRepository {
    val queried = mutableListOf<String>()
    val enabled = mutableListOf<Pair<String, String>>()
    val disabled = mutableListOf<String>()

    /** Set to make the flag write fail, the way a full or unwritable preference store would. */
    var recordFailure: Exception? = null

    override suspend fun biometricUnlockState(username: String): BiometricUnlockState {
        queried += username
        return BiometricUnlockState(availability = availability, enrolled = username in enrolled)
    }

    override suspend fun biometricAvailability(): BiometricAvailability = availability

    override suspend fun enable(username: String, password: String): Outcome<Unit> {
        enabled += username to password
        return Outcome.Success(Unit)
    }

    override suspend fun disable(username: String) {
        disabled += username
    }

    override suspend fun enrolmentOffered(username: String): Boolean = username in offered

    override suspend fun recordEnrolmentOffered(username: String) {
        recordFailure?.let { throw it }
        offered += username
    }
}
