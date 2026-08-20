package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.repository.BiometricUnlockRepository
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.logging.KLogger
import kotlinx.coroutines.CancellationException

/**
 * Claim the signed-in account's one chance to be asked "unlock with your fingerprint next time?".
 *
 * Biometric unlock is otherwise undiscoverable: the settings toggle has to be gone looking for, and
 * the login screen only shows a fingerprint once an enrolment already exists. This is the ask that
 * closes that loop, and it is deliberately made at the two moments — straight after signup and
 * straight after a password login — where the app is still holding the typed plaintext. After that
 * it is gone: [AppUser.LoggedIn.password] is the stored hash and salt, which is exactly why
 * enrolling from settings has to ask for the password a second time.
 *
 * ## Deciding and recording are one call
 *
 * A `should I ask?` predicate with a separate `remember that I did` would let a caller show the
 * dialog and forget to record it, and the failure mode of that bug is asking on every single login
 * forever. So the flag is spent here: a `true` return means the dialog may be shown *and* the
 * account's one offer has already been consumed. Recorded on the way out rather than on the user's
 * answer for the same reason — a process death while the dialog is up is still an ask the user saw,
 * and re-asking everyone who backgrounds the app on it is the nagging this flag exists to prevent.
 *
 * Enrolling from the dialog is [SetBiometricUnlock]'s job, unchanged and with the same verification;
 * this use case decides only whether to ask.
 */
class OfferBiometricUnlock(
    private val repository: BiometricUnlockRepository,
    private val userPreferences: UserPreferences,
) : Usecase<Unit, Boolean> {

    override suspend fun invoke(param: Unit): Boolean {
        // Resolved here, never passed in — the same rule SetBiometricUnlock follows, for a weaker
        // but related reason: a name from the caller could spend (or re-ask) the wrong account's
        // offer, and on a device with several accounts that is silent.
        val username = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName ?: return false

        val state = repository.biometricUnlockState(username)
        // NoHardware is the whole desktop story, so this never fires there. NotEnrolled is a real
        // device that could do this if the user registered a fingerprint — but sending somebody to
        // the system settings mid-login is a worse first impression than the settings toggle they
        // will find later, and it would spend the one offer on a dialog that cannot enrol.
        if (state.availability != BiometricAvailability.Available) return false
        if (state.enrolled) return false
        if (repository.enrolmentOffered(username)) return false

        return try {
            repository.recordEnrolmentOffered(username)
            true
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (failure: Exception) {
            // An offer that cannot be remembered is one that asks again at every login. Skipping it
            // costs this account a prompt it can still find in settings; showing it anyway costs
            // them the prompt every time they sign in.
            KLogger.e(failure) { "biometric unlock: could not record the enrolment offer for $username" }
            false
        }
    }
}
