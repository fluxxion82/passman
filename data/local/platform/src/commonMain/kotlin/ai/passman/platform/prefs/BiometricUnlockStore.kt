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

    /**
     * Whether this account has already been offered enrolment on its way into the app.
     *
     * Deliberately not derived from [read]. "Has an enrolment" and "has been asked about one" are
     * different facts with different lifetimes: turning the feature off in settings clears the
     * enrolment, and the account must not start being asked again on every login as a result.
     *
     * Survives [remove] for the same reason, and is keyed by username like the blob is — one
     * device, several accounts, one question each.
     */
    suspend fun enrolmentOffered(username: String): Boolean
    suspend fun recordEnrolmentOffered(username: String)
}
