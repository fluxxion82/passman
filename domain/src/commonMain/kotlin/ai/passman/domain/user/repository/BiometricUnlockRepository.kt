package ai.passman.domain.user.repository

import ai.passman.domain.base.model.Outcome
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
     * Verify [password] against the stored credential and, only if it holds, wrap it under a
     * freshly generated biometric-gated key. Prompts.
     */
    suspend fun enable(username: String, password: String): Outcome<Unit>

    /**
     * Throw the wrapped copy and its key away. Never fails: this is also the cleanup path for an
     * account whose enrolment has already been invalidated out from under it.
     */
    suspend fun disable(username: String)
}
