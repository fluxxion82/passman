package ai.passman.platform.prefs

import ai.passman.platform.service.WrappedSecret

/**
 * Where an account's biometric enrolment lives between sessions.
 *
 * Only ever the *sealed* master password. The plaintext exists for the length of one enrolment call
 * and one unlock call and is never handed to this interface, which is the whole reason the blob is
 * safe in ordinary preferences: without the hardware key it decrypts to nothing, on this device or
 * any other.
 *
 * Keyed by username because a device can hold several accounts and each has its own key; wiping one
 * account's enrolment must not touch another's.
 */
interface BiometricUnlockStore {
    suspend fun read(username: String): WrappedSecret?
    suspend fun write(username: String, wrapped: WrappedSecret)
    suspend fun remove(username: String)
}
