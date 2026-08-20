package ai.passman.crypto.vault

import kotlin.coroutines.ExperimentalStdlibCoroutineSupportApi
import kotlin.coroutines.debug.StackTraceRecoverable

/**
 * Why a keyring or vault artifact could not be opened.
 *
 * This exists in `commonMain` for two reasons. First, `VaultCipher` is consumed by `commonMain`
 * repositories that also compile for iOS, where `javax.crypto.AEADBadTagException` is not a nameable
 * type — a common-code caller could otherwise only write `catch (e: Exception)`. Second, login has to
 * tell the user "wrong password" (retype it) apart from "this file is damaged" (restore a backup);
 * those are different messages and different recovery paths, and a raw `AEADBadTagException` is the
 * same object for both.
 *
 * **The split is a usability affordance, not a cryptographic distinguisher.** A single AES-GCM tag
 * failure carries exactly one bit of information: the key, nonce, associated data and ciphertext did
 * not agree. Nothing in it says *which* of those was wrong. The classification below is keyed on
 * which artifact failed and how far its structural validation got, not on any property of the tag:
 *
 * - The keyring is the artifact the password is applied to, so a tag failure there is reported as
 *   [WrongPassword] — that is overwhelmingly the common cause and the only one the user can act on.
 *   A tampered keyring whose header still validates is genuinely indistinguishable from a typo and
 *   is reported the same way.
 * - The vault is opened with a session key that a successful keyring unwrap already authenticated,
 *   so a tag failure there cannot be a password problem and is reported as [Tampered].
 *
 * Do not add a distinguisher. There isn't one.
 *
 * **Nothing that came out of the artifact may appear in a [message].** These are thrown on the read
 * path for files full of ciphertext, and a platform parser's message is not safe to forward: for a
 * damaged legacy vault, `kotlinx.serialization`'s `JsonDecodingException` embeds the very bytes it
 * failed to parse. A message here is a fixed string plus, at most, a length or a header field —
 * never a payload byte, and never another exception's text.
 */
sealed class VaultFailure(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** The password did not unwrap the keyring. Recoverable: the user retypes it. */
    class WrongPassword(cause: Throwable? = null) : VaultFailure("wrong password", cause)

    /**
     * Authentication failed on intact-looking structure. Retyping the password will not help, but
     * *which* artifact to replace is not decided here, because a GCM tag failure cannot say.
     *
     * Two states produce this, and they need opposite recoveries:
     * - the artifact was tampered with or damaged, and has to be restored from a backup;
     * - the artifact is perfectly intact but the wrong key was applied to it — a restore that pairs
     *   keyring A with vault B, or a legacy vault read with another account's RSA identity. Here the
     *   vault is fine and it is the *key material* that is wrong.
     *
     * Recovery guidance built on this must name both possibilities rather than telling the user their
     * vault is corrupt, which for the second state is false and destructive advice.
     */
    class Tampered(message: String, cause: Throwable? = null) : VaultFailure(message, cause)

    /**
     * The artifact cannot be read as presented, before any key is applied: bad magic, unsupported
     * version or suite, an out-of-range cost parameter, truncation or trailing bytes, unparseable
     * legacy content, or a legacy envelope whose legacy unwrapping key is unavailable on this device.
     *
     * @property legacyKeyUnavailable true only for that last case: the bytes are a legacy envelope
     *   this device cannot open because the legacy RSA identity (the PKCS#12 store) is missing, not
     *   because the vault is damaged. The two need different recoveries — restore the identity store
     *   versus restore the vault — and callers must switch on this flag rather than on [message],
     *   which is prose and will be reworded.
     */
    @OptIn(ExperimentalStdlibCoroutineSupportApi::class)
    class Malformed(
        message: String,
        cause: Throwable? = null,
        val legacyKeyUnavailable: Boolean = false,
    ) : VaultFailure(message, cause), StackTraceRecoverable<Malformed> {
        // Coroutine stack trace recovery copies exceptions reflectively via a (message, cause)
        // constructor, which this class does not have — so a Malformed rethrown across a
        // suspension kept its original (less useful) trace and, worse, any future reflective
        // copy would default legacyKeyUnavailable to false and send the caller down the wrong
        // recovery path. This copy carries the flag explicitly.
        override fun copyForStackTraceRecovery(): Malformed =
            Malformed(message ?: "malformed vault artifact", this, legacyKeyUnavailable)
    }
}
