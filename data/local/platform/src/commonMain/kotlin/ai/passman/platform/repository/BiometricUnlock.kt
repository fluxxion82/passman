package ai.passman.platform.repository

import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.exception.AuthFailure
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState
import ai.passman.platform.prefs.BiometricUnlockStore
import ai.passman.platform.service.BioAuthFailure
import ai.passman.platform.service.BioAuthService
import kotlinx.coroutines.CancellationException

/**
 * The policy around [BioAuthService]: which account owns which key, when an enrolment is thrown
 * away, and what the user is told when a prompt does not produce a password.
 *
 * Kept apart from both the platform service and [LocalUserRepository] because it is the only part
 * of biometric unlock that is *decidable* — everything below it needs a fingerprint sensor and
 * everything above it needs a keyring and a vault. All of the behaviour worth pinning lives here.
 *
 * ## What is wrapped, and why it is the master password
 *
 * The obvious alternative is to wrap the device master key and skip the KDF on a biometric login.
 * It would be faster and it would be worse: the login path would fork, and the biometric fork would
 * be the one that never runs the credential check, never upgrades a legacy KDF, and never resumes
 * an interrupted password change. Wrapping the password the user typed means the fork rejoins
 * immediately — [LocalUserRepository.bioLogin] hands the recovered string to the ordinary
 * `login`, and every invariant that path already has applies unchanged.
 *
 * It also fails safe in the one case that matters. If the master password is changed on another
 * device and this device's vault syncs, the wrapped copy is stale; the recovered string simply
 * fails the ordinary credential check and the user is asked to type it. A wrapped master *key*
 * would have been accepted.
 */
class BiometricUnlock(
    private val bioAuthService: BioAuthService,
    private val store: BiometricUnlockStore,
) {

    suspend fun state(username: String): BiometricUnlockState = BiometricUnlockState(
        availability = availability(),
        enrolled = store.read(username) != null,
    )

    /** The device half of [state], for callers with no account to ask about yet. */
    suspend fun availability(): BiometricAvailability = bioAuthService.canAuthenticate()

    /**
     * Seal [masterPassword] under a fresh biometric-gated key for [username].
     *
     * Callers must already have verified [masterPassword]; this deliberately does not, because the
     * check belongs where the stored credential and the hasher live, and duplicating it here would
     * mean two implementations of "is this the right password" that can drift apart.
     */
    suspend fun enroll(username: String, masterPassword: String): Outcome<Unit> {
        val availability = bioAuthService.canAuthenticate()
        if (availability != BiometricAvailability.Available) return availability.asError()

        val secret = masterPassword.encodeToByteArray()
        return try {
            when (val outcome = bioAuthService.enroll(alias(username), secret)) {
                is BioAuthService.EnrollOutcome.Enrolled -> {
                    store.write(username, outcome.wrapped)
                    KLogger.d { "biometric unlock: enrolled $username" }
                    Outcome.Success(Unit)
                }
                is BioAuthService.EnrollOutcome.Failed -> {
                    // A half-made enrolment is worse than none: the key may exist with nothing
                    // stored against it, or a previous enrolment's blob may now outlive the key
                    // that enroll() replaced. Clear both ends before reporting.
                    clear(username)
                    outcome.reason.asError()
                }
            }
        } finally {
            secret.fill(0)
        }
    }

    /**
     * Recover [username]'s master password. The prompt is the only way to reach the key, so a
     * success here is a statement about hardware, not about a callback the app chose to believe.
     */
    suspend fun unlock(username: String): Outcome<String> {
        val wrapped = store.read(username)
            ?: return Outcome.Error("Biometric unlock is not set up for this account", AuthFailure.BioAuthNotSetUp)

        val availability = bioAuthService.canAuthenticate()
        if (availability != BiometricAvailability.Available) return availability.asError()

        return when (val outcome = bioAuthService.unlock(alias(username), wrapped)) {
            is BioAuthService.UnlockOutcome.Unlocked -> {
                val secret = outcome.secret
                try {
                    Outcome.Success(secret.decodeToString())
                } finally {
                    secret.fill(0)
                }
            }
            is BioAuthService.UnlockOutcome.Failed -> {
                // The invalidated case is the security property doing its job, so the enrolment is
                // retired here rather than left to rot: leaving the blob behind would keep offering
                // a button that cannot work, and would keep a copy of the master password on disk
                // for a key that no longer exists.
                if (outcome.reason == BioAuthFailure.PermanentlyInvalidated) clear(username)
                outcome.reason.asError()
            }
        }
    }

    /**
     * Forget [username]'s enrolment: the stored blob first, then the key.
     *
     * That order is not arbitrary. Blob-then-key means the worst interruption leaves a key nothing
     * points at, which is inert; key-then-blob leaves a blob that looks like a working enrolment and
     * fails at the sensor.
     */
    suspend fun disable(username: String) = clear(username)

    /**
     * Whether [username] has already had its one chance to be offered enrolment.
     *
     * A pass-through to the store, kept on this class rather than wiring the store into
     * [LocalUserRepository] as well: everything else about enrolment is decided here, and a second
     * holder of the same preferences file is a second place for the key naming to drift.
     */
    suspend fun enrolmentOffered(username: String): Boolean = store.enrolmentOffered(username)

    suspend fun recordEnrolmentOffered(username: String) = store.recordEnrolmentOffered(username)

    private suspend fun clear(username: String) {
        runCatching { store.remove(username) }
            .onFailure {
                if (it is CancellationException) throw it
                KLogger.e(it) { "biometric unlock: could not remove the stored enrolment for $username" }
            }
        runCatching { bioAuthService.discard(alias(username)) }
            .onFailure {
                if (it is CancellationException) throw it
                KLogger.e(it) { "biometric unlock: could not discard the hardware key for $username" }
            }
    }

    /**
     * One key per account, under a namespaced alias.
     *
     * The keystore is shared with every other key this app holds, so a bare username would collide
     * with any alias a user happens to pick for a keystore entry — and a collision here silently
     * re-points an account's unlock at somebody else's key.
     */
    private fun alias(username: String) = "$ALIAS_PREFIX$username"

    /**
     * Each case gets a sentence that tells the user what to do, because the login screen shows
     * exactly this string and nothing else. "Auth failed" for all five — which is what the old
     * single failure produced — is indistinguishable from a bug.
     */
    private fun BioAuthFailure.asError(): Outcome.Error = when (this) {
        BioAuthFailure.Cancelled ->
            Outcome.Error("Biometric unlock was cancelled", AuthFailure.BioAuthCancelled)
        BioAuthFailure.Failed ->
            Outcome.Error("Biometric unlock failed. Try again or use your password", AuthFailure.BioAuthFailed)
        BioAuthFailure.Lockout ->
            Outcome.Error("Too many biometric attempts. Sign in with your password", AuthFailure.BioAuthLockedOut)
        BioAuthFailure.PermanentlyInvalidated ->
            Outcome.Error(
                "Biometric unlock was turned off because this device's biometrics changed. " +
                    "Sign in with your password",
                AuthFailure.BioAuthInvalidated,
            )
        BioAuthFailure.Unavailable ->
            Outcome.Error("Biometric unlock is unavailable on this device", AuthFailure.BioAuthUnavailable)
    }

    private fun BiometricAvailability.asError(): Outcome.Error = when (this) {
        BiometricAvailability.NotEnrolled ->
            Outcome.Error("Register a fingerprint or face on this device first", AuthFailure.BioAuthNotEnrolled)
        BiometricAvailability.NoHardware ->
            Outcome.Error("This device has no biometric hardware", AuthFailure.BioAuthUnavailable)
        // Available never reaches here — the callers check for it before asking for a message.
        BiometricAvailability.Available, BiometricAvailability.Unavailable ->
            Outcome.Error("Biometric unlock is unavailable right now", AuthFailure.BioAuthUnavailable)
    }

    private companion object {
        const val ALIAS_PREFIX = "passman.biometric-unlock."
    }
}
