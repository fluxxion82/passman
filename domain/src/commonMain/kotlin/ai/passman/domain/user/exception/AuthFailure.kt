package ai.passman.domain.user.exception

import ai.passman.domain.exception.Failure

sealed class AuthFailure {
    object SignupFailure : Failure.FeatureFailure()
    object LoginFailure : Failure.FeatureFailure()
    data class GeneralAuthFailure(val message: String?) : Failure.FeatureFailure()
    data class ServerError(val message: String?) : Failure.FeatureFailure()
    object InvalidPassword : Failure.FeatureFailure()
    object NoStoredCredentials : Failure.FeatureFailure()
    object AccountAlreadyExists : Failure.FeatureFailure()
    object KeystoreCreationFailure : Failure.FeatureFailure()

    /*
     * Biometric unlock, one case per thing the user has to do next. These used to be a single
     * `BioAuthFailed`, which put "you tapped cancel", "the sensor is wet", "you are locked out for
     * 30 seconds" and "your enrolment is gone and will not come back" behind one "Auth failed"
     * snackbar — three of those are self-correcting and one requires the user to go and re-enable
     * the feature, so collapsing them hid the only message that mattered.
     */

    /**
     * Everything the biometric layer can report, under one type.
     *
     * Callers need to ask "did this come from the sensor?" — the login throttle must not count a
     * dismissed prompt as a password guess, and the login screen re-reads its enrolment state after
     * one of these. A sealed parent answers that by construction; a hand-written list of the seven
     * objects below would answer it until somebody added an eighth.
     */
    sealed class BiometricFailure : Failure.FeatureFailure()

    /** The device has no biometric hardware, or nothing can host a prompt right now. */
    object BioAuthUnavailable : BiometricFailure()

    /** Hardware exists, but the user has registered no biometrics with the OS. */
    object BioAuthNotEnrolled : BiometricFailure()

    /** This account has no wrapped master password — biometric unlock was never switched on. */
    object BioAuthNotSetUp : BiometricFailure()

    /** The user dismissed the prompt. Not a failure to report as one. */
    object BioAuthCancelled : BiometricFailure()

    /** The sensor ran and said no, or the wrapped secret would not unseal. */
    object BioAuthFailed : BiometricFailure()

    /** Too many attempts; the platform has locked the sensor out for a while. */
    object BioAuthLockedOut : BiometricFailure()

    /**
     * The hardware key is gone for good — the property that makes this feature safe. Registering a
     * new fingerprint (or clearing them all) invalidates the key, so an attacker who adds their own
     * finger to an unlocked phone gets an unusable key rather than the vault. The enrolment has
     * been cleared by the time this is reported; the user signs in with their password and, if they
     * want it back, switches the feature on again.
     */
    object BioAuthInvalidated : BiometricFailure()
}
