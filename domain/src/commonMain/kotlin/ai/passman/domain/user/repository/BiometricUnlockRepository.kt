package ai.passman.domain.user.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.models.BiometricUnlockState

/**
 * Enrolment side of passwordless biometric unlock.
 *
 * A fingerprint derives nothing, so unlocking cannot be "biometrics instead of a password" in any
 * cryptographic sense. What actually happens is that the master password is sealed under a
 * hardware key the sensor gates, and the login path afterwards is byte-for-byte the ordinary
 * password login. That is why [enable] takes the master password and nothing else does: the only
 * moment a copy can be made is a moment the user has just proved they know it.
 *
 * Deliberately separate from [UserRepository] rather than another handful of methods on it: the
 * whole surface is unimplementable without platform key storage, and a platform that has none
 * (iOS today) leaves it unbound instead of stubbing four more methods that throw.
 */
interface BiometricUnlockRepository {
    /** Cheap enough to call on every keystroke of the login screen's username field. */
    suspend fun biometricUnlockState(username: String): BiometricUnlockState

    /**
     * What the device can do, with no account in the picture.
     *
     * Separate from [biometricUnlockState] because the signup form has no account to ask about: it
     * is deciding whether to draw a checkbox for a name that does not exist yet, and answering that
     * through a per-account query would mean inventing a username to ask about.
     */
    suspend fun biometricAvailability(): BiometricAvailability

    /**
     * Verify [password] against the stored credential and, only if it holds, wrap it under a
     * freshly generated biometric-gated key. Prompts.
     */
    suspend fun enable(username: String, password: String): Outcome<Unit>

    /**
     * Throw the wrapped copy and its key away. Never fails: this is also the cleanup path for an
     * account whose enrolment has already been invalidated out from under it.
     */
    suspend fun disable(username: String)

    /**
     * Whether [username] has already been offered enrolment on its way into the app.
     *
     * Stored rather than inferred, and stored per account, because the question this answers is
     * "has this person already said no?" — which nothing else on this interface records. It
     * outlives [disable] deliberately: an account that switched the feature off in settings has
     * answered, and must not be asked again at every login for having done so.
     */
    suspend fun enrolmentOffered(username: String): Boolean

    /** Remember that [username] has been asked, whatever the answer turns out to be. */
    suspend fun recordEnrolmentOffered(username: String)
}
