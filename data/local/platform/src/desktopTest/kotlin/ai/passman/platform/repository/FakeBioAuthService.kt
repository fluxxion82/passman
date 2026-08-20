package ai.passman.platform.repository

import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.platform.service.BioAuthFailure
import ai.passman.platform.service.BioAuthService
import ai.passman.platform.service.WrappedSecret

/**
 * A [BioAuthService] that behaves like a hardware keystore without needing one.
 *
 * It is not a stub that returns canned answers: the "key" is a per-alias mask, sealing XORs the
 * secret with it, and unsealing needs the mask to still be there. So a discarded (or never
 * generated) key really does make the stored blob unopenable, which is exactly the property the
 * tests around invalidation are asserting. A fake that remembered the plaintext and handed it back
 * would pass those tests no matter what the code did.
 */
class FakeBioAuthService(
    var availability: BiometricAvailability = BiometricAvailability.Available,
) : BioAuthService {

    /** The aliases that currently hold a key, and the mask each one seals with. */
    private val keys = mutableMapOf<String, Byte>()

    /** Set to make the next (and every later) enrol fail with this reason. */
    var enrollFailure: BioAuthFailure? = null

    /** Set to make the next (and every later) unlock fail with this reason. */
    var unlockFailure: BioAuthFailure? = null

    /** Aliases whose key this service was asked to destroy, in order. */
    val discarded = mutableListOf<String>()

    /** The secrets [enroll] was handed, so a test can prove what was wrapped. */
    val enrolledSecrets = mutableListOf<String>()

    fun hasKey(alias: String): Boolean = alias in keys

    override suspend fun canAuthenticate(): BiometricAvailability = availability

    override suspend fun enroll(alias: String, secret: ByteArray): BioAuthService.EnrollOutcome {
        enrollFailure?.let { return BioAuthService.EnrollOutcome.Failed(it) }
        val mask = ((keys.size + 1) * 37).toByte().let { if (it.toInt() == 0) 1 else it }
        keys[alias] = mask
        enrolledSecrets += secret.decodeToString()
        return BioAuthService.EnrollOutcome.Enrolled(
            WrappedSecret(
                ciphertext = ByteArray(secret.size) { (secret[it].toInt() xor mask.toInt()).toByte() },
                iv = ByteArray(IV_BYTES) { it.toByte() },
            ),
        )
    }

    override suspend fun unlock(alias: String, wrapped: WrappedSecret): BioAuthService.UnlockOutcome {
        unlockFailure?.let { return BioAuthService.UnlockOutcome.Failed(it) }
        // No key means the enrolment is over — the same answer the real service gives when the
        // keystore has thrown the key away because the device's biometrics changed.
        val mask = keys[alias] ?: return BioAuthService.UnlockOutcome.Failed(BioAuthFailure.PermanentlyInvalidated)
        val plain = ByteArray(wrapped.ciphertext.size) { (wrapped.ciphertext[it].toInt() xor mask.toInt()).toByte() }
        return BioAuthService.UnlockOutcome.Unlocked(plain)
    }

    override suspend fun discard(alias: String) {
        discarded += alias
        keys.remove(alias)
    }

    private companion object {
        const val IV_BYTES = 12
    }
}
