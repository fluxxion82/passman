package ai.passman.platform.repository

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.impl.LocalBiometricUnlockPreferences
import ai.passman.platform.service.BioAuthFailure
import com.russhwolf.settings.MapSettings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * The decidable half of biometric unlock.
 *
 * The failure this suite exists to prevent is an enrolment that outlives the key it depends on. A
 * stored blob whose key is gone is not merely broken — it is a copy of the master password sitting
 * on disk for a lock that no longer exists, and a login button that can only ever fail. So the
 * questions asked below are all the same one from different directions: **after this, does the
 * stored enrolment still correspond to a usable key?**
 *
 * The store is the real [LocalBiometricUnlockPreferences] over an in-memory `Settings`, so the
 * round-trip through JSON and Base64 is covered too; only the sensor is faked, and
 * [FakeBioAuthService] fakes it with a real seal rather than a remembered plaintext.
 */
class BiometricUnlockTest {

    private val user = "alice"
    private val masterPassword = "correct horse battery staple"
    private val alias = "passman.biometric-unlock.$user"

    private val settings = MapSettings()
    private val service = FakeBioAuthService()
    private val store = LocalBiometricUnlockPreferences(
        encryptedFactory = object : EncryptionSettingsFactory {
            override fun createEncrypted(name: String) = settings
        },
        coroutinesContextFacade = UnconfinedFacade,
    )
    private val unlock = BiometricUnlock(bioAuthService = service, store = store)

    @Test
    fun `unlock returns the password that was enrolled`() = runBlocking {
        assertIs<Outcome.Success<Unit>>(unlock.enroll(user, masterPassword))

        val recovered = unlock.unlock(user)

        assertIs<Outcome.Success<String>>(recovered)
        assertEquals(masterPassword, recovered.value)
    }

    /**
     * The blob on disk must be the sealed form, not the password. This is the single assertion that
     * would have caught "store the password and gate the UI on a boolean".
     */
    @Test
    fun `the stored enrolment never contains the plaintext password`() = runBlocking {
        unlock.enroll(user, masterPassword)

        val stored = store.read(user)
        assertNotNull(stored)
        assertNotEquals(masterPassword, stored.ciphertext.decodeToString())
        assertFalse(
            settings.keys.any { key -> settings.getStringOrNull(key)?.contains(masterPassword) == true },
            "the master password must not appear anywhere in the preference store",
        )
    }

    @Test
    fun `an account with no enrolment reports not set up rather than prompting`() = runBlocking {
        val outcome = unlock.unlock(user)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthNotSetUp, outcome.cause)
        assertTrue(service.discarded.isEmpty(), "nothing was enrolled, so nothing should be destroyed")
    }

    /**
     * The security property. A new fingerprint invalidates the key; the enrolment has to go with
     * it, or the device keeps a copy of the master password for a lock that cannot be opened.
     */
    @Test
    fun `a permanently invalidated key clears the enrolment`() = runBlocking {
        unlock.enroll(user, masterPassword)
        service.unlockFailure = BioAuthFailure.PermanentlyInvalidated

        val outcome = unlock.unlock(user)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthInvalidated, outcome.cause)
        assertNull(store.read(user), "the wrapped master password must not survive its key")
        assertContentEquals(listOf(alias), service.discarded, "the key is destroyed as well as the blob")
        assertFalse(unlock.state(user).enrolled)
    }

    /** Only the permanent case retires the enrolment; the recoverable ones must leave it alone. */
    @Test
    fun `a cancelled prompt leaves the enrolment in place`() = runBlocking {
        unlock.enroll(user, masterPassword)
        service.unlockFailure = BioAuthFailure.Cancelled

        val outcome = unlock.unlock(user)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthCancelled, outcome.cause)
        assertTrue(unlock.state(user).enrolled, "a dismissed prompt is not a reason to forget the account")
        assertTrue(service.discarded.isEmpty())
    }

    @Test
    fun `a lockout leaves the enrolment in place`() = runBlocking {
        unlock.enroll(user, masterPassword)
        service.unlockFailure = BioAuthFailure.Lockout

        val outcome = unlock.unlock(user)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthLockedOut, outcome.cause)
        assertTrue(unlock.state(user).enrolled)
    }

    /**
     * Every reason gets its own sentence. The old implementation collapsed all of these into one
     * "Auth failed" snackbar, which is how "your enrolment is gone" and "you tapped cancel" became
     * indistinguishable to the user.
     */
    @Test
    fun `every failure reason maps to its own message and cause`() = runBlocking {
        val seen = BioAuthFailure.entries.map { reason ->
            unlock.enroll(user, masterPassword)
            service.unlockFailure = reason
            val outcome = unlock.unlock(user)
            assertIs<Outcome.Error>(outcome)
            service.unlockFailure = null
            outcome.message to outcome.cause
        }

        assertEquals(BioAuthFailure.entries.size, seen.map { it.first }.toSet().size, "messages must be distinct")
        assertEquals(BioAuthFailure.entries.size, seen.map { it.second }.toSet().size, "causes must be distinct")
    }

    @Test
    fun `unlock refuses before prompting when no biometric is registered on the device`() = runBlocking {
        unlock.enroll(user, masterPassword)
        service.availability = BiometricAvailability.NotEnrolled
        service.unlockFailure = BioAuthFailure.Failed // would fire if the gate were skipped

        val outcome = unlock.unlock(user)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthNotEnrolled, outcome.cause)
        assertTrue(unlock.state(user).enrolled, "the account is fine; the device is not")
    }

    @Test
    fun `enrol refuses on hardware that cannot authenticate`() = runBlocking {
        service.availability = BiometricAvailability.NoHardware

        val outcome = unlock.enroll(user, masterPassword)

        assertIs<Outcome.Error>(outcome)
        assertEquals(AuthFailure.BioAuthUnavailable, outcome.cause)
        assertNull(store.read(user), "nothing may be written when the prompt could not have run")
        assertTrue(service.enrolledSecrets.isEmpty())
    }

    /**
     * A prompt the user walks away from must not leave a key with nothing sealed under it, nor a
     * previous enrolment's blob pointing at a key that `enroll` has already replaced.
     */
    @Test
    fun `a failed enrol leaves neither a stored blob nor a key`() = runBlocking {
        unlock.enroll(user, masterPassword)
        service.enrollFailure = BioAuthFailure.Cancelled

        val outcome = unlock.enroll(user, "a different password")

        assertIs<Outcome.Error>(outcome)
        assertNull(store.read(user))
        assertFalse(service.hasKey(alias))
        assertFalse(unlock.state(user).enrolled)
    }

    @Test
    fun `disable removes both the stored blob and the key`() = runBlocking {
        unlock.enroll(user, masterPassword)

        unlock.disable(user)

        assertNull(store.read(user))
        assertFalse(service.hasKey(alias))
        assertContentEquals(listOf(alias), service.discarded)
    }

    /** One key per account: disabling one must not disturb another signed-in account's enrolment. */
    @Test
    fun `disabling one account leaves another account enrolled`() = runBlocking {
        unlock.enroll(user, masterPassword)
        unlock.enroll("bob", "bob's password")

        unlock.disable(user)

        assertFalse(unlock.state(user).enrolled)
        assertTrue(unlock.state("bob").enrolled)
        val bob = unlock.unlock("bob")
        assertIs<Outcome.Success<String>>(bob)
        assertEquals("bob's password", bob.value)
    }

    @Test
    fun `state reports the device availability alongside the account enrolment`() = runBlocking {
        assertEquals(BiometricAvailability.Available, unlock.state(user).availability)
        assertFalse(unlock.state(user).canUnlock, "available hardware is not an enrolment")

        unlock.enroll(user, masterPassword)
        assertTrue(unlock.state(user).canUnlock)

        service.availability = BiometricAvailability.NotEnrolled
        assertFalse(unlock.state(user).canUnlock, "an enrolment is useless with no biometric to unlock it")
    }

    /** Re-enrolling has to replace the wrapped copy, not leave the previous password recoverable. */
    @Test
    fun `re-enrolling replaces the wrapped password`() = runBlocking {
        unlock.enroll(user, masterPassword)
        unlock.enroll(user, "a new master password")

        val recovered = unlock.unlock(user)

        assertIs<Outcome.Success<String>>(recovered)
        assertEquals("a new master password", recovered.value)
    }

    // ------------------------------------------------- the one-time enrolment offer

    @Test
    fun `an account is not offered until it has been`() = runBlocking {
        assertFalse(unlock.enrolmentOffered(user))

        unlock.recordEnrolmentOffered(user)

        assertTrue(unlock.enrolmentOffered(user))
    }

    /** One question per account: asking one must not silence the other. */
    @Test
    fun `recording one account's offer leaves another account's alone`() = runBlocking {
        unlock.recordEnrolmentOffered(user)

        assertFalse(unlock.enrolmentOffered("bob"))
    }

    /**
     * The flag records that the user was *asked*, not that they are enrolled. Turning the feature
     * off in settings is an answer; re-asking at every login because of it is the nagging the flag
     * exists to prevent.
     */
    @Test
    fun `turning biometric unlock off does not un-ask the offer`() = runBlocking {
        unlock.recordEnrolmentOffered(user)
        unlock.enroll(user, masterPassword)

        unlock.disable(user)

        assertFalse(unlock.state(user).enrolled)
        assertTrue(unlock.enrolmentOffered(user), "the account has already been asked once")
    }

    /** Same reason, for the case the user did not choose: the key going away is not a new answer. */
    @Test
    fun `an invalidated enrolment does not un-ask the offer`() = runBlocking {
        unlock.recordEnrolmentOffered(user)
        unlock.enroll(user, masterPassword)
        service.unlockFailure = BioAuthFailure.PermanentlyInvalidated

        unlock.unlock(user)

        assertNull(store.read(user))
        assertTrue(unlock.enrolmentOffered(user))
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = Dispatchers.Unconfined
    }
}
