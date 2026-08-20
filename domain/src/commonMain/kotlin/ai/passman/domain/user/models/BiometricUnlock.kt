package ai.passman.domain.user.models

/**
 * What the device can do about biometrics right now, independent of any account.
 *
 * The three failing cases are kept apart because the user's next move differs: [NoHardware] means
 * the setting should not be offered at all, [NotEnrolled] means "go register a fingerprint", and
 * [Unavailable] is the temporary bucket (sensor busy, a pending security patch, no foreground
 * Activity to host the prompt) where "try again" is the right advice.
 */
enum class BiometricAvailability {
    Available,
    NoHardware,
    NotEnrolled,
    Unavailable,
}

/**
 * Whether biometric unlock can actually be used for one account on this device.
 *
 * Two independent facts, because either can change without the other: the user can delete their
 * fingerprints (availability drops) or the account's wrapped master password can be thrown away
 * (enrolment drops) — and the login screen must only offer the button when both hold, while the
 * settings screen has to distinguish "cannot" from "not switched on" to draw the right row.
 */
data class BiometricUnlockState(
    val availability: BiometricAvailability,
    val enrolled: Boolean,
) {
    val canUnlock: Boolean get() = availability == BiometricAvailability.Available && enrolled

    /**
     * Whether the settings toggle is worth drawing. Hardware that does not exist never will, so
     * that one row is hidden rather than shown permanently disabled; every other state is
     * recoverable by the user and the row explains itself when they tap it.
     */
    val offerable: Boolean get() = availability != BiometricAvailability.NoHardware

    companion object {
        val Unsupported = BiometricUnlockState(BiometricAvailability.NoHardware, enrolled = false)
    }
}
