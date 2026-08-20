package ai.passman.platform.service

import ai.passman.domain.user.models.BiometricAvailability

/**
 * The platform half of passwordless biometric unlock: a hardware-held key that a biometric gates.
 *
 * ## Why the shape changed
 *
 * The previous contract was a single `authenticate(hardwareKeySeed: ByteArray?)` returning
 * success/failure. Both of its call sites passed null, so the `CryptoObject` branch never ran and
 * the result was a **bare boolean from a callback** — nothing cryptographic depended on it, and a
 * forged success (a hooked callback, a patched APK, a `BiometricPrompt` shim) was indistinguishable
 * from a real one. Worse, callers still demanded the typed master password alongside it, so the
 * feature cost the user a fingerprint and bought them nothing.
 *
 * A fingerprint cannot derive a key; there is no biometric-shaped secret to build a vault password
 * out of. The only honest construction is the one below: a key that lives in hardware, that the
 * platform refuses to use until a biometric has matched, sealing a copy of the master password.
 * Then "the sensor said yes" is not something the app has to believe — without it, [unlock] has no
 * usable key and returns nothing at all.
 *
 * ## What implementations must guarantee
 *
 * - The key is per-[alias] (one per account) and generated fresh by every [enroll].
 * - The key requires a biometric **per operation**, not per time window. That is what forces the
 *   cipher to travel through the prompt rather than merely being used after it.
 * - Enrolling a new biometric with the OS destroys the key. This is the property that stops an
 *   attacker adding their own finger to a phone they have taken; it surfaces as
 *   [BioAuthFailure.PermanentlyInvalidated] and the caller clears the enrolment.
 * - The plaintext secret is never persisted anywhere by the implementation.
 */
interface BioAuthService {
    /** Whether a prompt could run at all. Free of any account's enrolment state. */
    suspend fun canAuthenticate(): BiometricAvailability

    /**
     * Generate a fresh biometric-gated key for [alias], prompt, and seal [secret] under it.
     *
     * Replaces any previous key for the alias: a re-enrolment whose old key survived would leave a
     * key nothing references, and any blob still stored against it would decrypt to a stale
     * password.
     */
    suspend fun enroll(alias: String, secret: ByteArray): EnrollOutcome

    /** Prompt, and on a match unseal [wrapped] with [alias]'s key. */
    suspend fun unlock(alias: String, wrapped: WrappedSecret): UnlockOutcome

    /** Destroy [alias]'s key. Silent about an alias that has none. */
    suspend fun discard(alias: String)

    sealed interface EnrollOutcome {
        data class Enrolled(val wrapped: WrappedSecret) : EnrollOutcome
        data class Failed(val reason: BioAuthFailure) : EnrollOutcome
    }

    sealed interface UnlockOutcome {
        /** [secret] is live key material; the caller copies what it needs and zeroes it. */
        class Unlocked(val secret: ByteArray) : UnlockOutcome
        data class Failed(val reason: BioAuthFailure) : UnlockOutcome
    }
}

/**
 * Why a prompt did not produce a secret.
 *
 * Five cases rather than one because the caller's *response* differs for each — three are
 * self-correcting, one is the platform throttling and one is permanent and destroys the enrolment.
 * The old contract had a single `Failed`, which is how "your enrolment is gone forever" ended up
 * behind the same snackbar as "you tapped cancel".
 */
enum class BioAuthFailure {
    /** The user dismissed the prompt or pressed the negative button. */
    Cancelled,

    /** The sensor ran and did not match, or the sealed bytes would not open. */
    Failed,

    /** Too many attempts; the platform has locked the sensor for a while. */
    Lockout,

    /** The key is gone and is not coming back — biometrics were added, removed or reset. */
    PermanentlyInvalidated,

    /** No hardware, no foreground host for the prompt, or the platform refused outright. */
    Unavailable,
}

/**
 * A secret sealed under a biometric-gated key: the ciphertext and the IV it was produced with.
 *
 * Both halves are stored and both are useless without the hardware key, which is why they can live
 * in ordinary preferences. Kept together as one value because a half-written pair is an enrolment
 * that cannot be opened and cannot be diagnosed.
 */
class WrappedSecret(val ciphertext: ByteArray, val iv: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is WrappedSecret && ciphertext.contentEquals(other.ciphertext) && iv.contentEquals(other.iv)

    override fun hashCode(): Int = 31 * ciphertext.contentHashCode() + iv.contentHashCode()

    /** Never the bytes: this ends up in logs the moment somebody interpolates the object. */
    override fun toString(): String = "WrappedSecret(ciphertext=${ciphertext.size}B, iv=${iv.size}B)"
}
