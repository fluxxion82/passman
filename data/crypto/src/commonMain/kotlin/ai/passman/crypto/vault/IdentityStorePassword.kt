package ai.passman.crypto.vault

import kotlin.jvm.JvmInline

/**
 * Proof that a password came out of the device keyring rather than out of a person.
 *
 * ## Why a type and not a comment
 *
 * The account identity store is written at a deliberately negligible PKCS#12 work factor
 * (`LowPbePkcs12Writer.ITERATIONS`). That is sound for exactly one reason: the password sealing it is
 * 256 bits of HKDF output from the device master key, so there is no guessing attack for a work
 * factor to slow down. It is a **downgrade attack** for anything a human typed, where the iteration
 * count is the only thing standing between a stolen data directory and the vault.
 *
 * That invariant used to live in KDoc on three `String` parameters, which is to say it lived nowhere:
 * any caller could pass any string and the compiler would agree. This type moves it into the
 * signature. The low-PBE write paths — `KeystoreClient`'s three identity methods and
 * `KeystoreLifecycle`'s — demand one of these, and the only way to obtain one in production is
 * [VaultCipher.identityStorePassword], which is the derivation itself.
 *
 * Probes that legitimately take either password ([ai.passman.platform.service.KeystoreLifecycle.canOpenKeystore]
 * has to try the *login* password on a pre-keyring account) keep taking a plain `String`. Only the
 * writes are fenced, because only the writes can do the damage.
 *
 * ## The escape hatch
 *
 * The primary constructor is private, so [unsafeNotFromKeyring] is the whole of the hole and it is
 * one grep away. It exists because test fixtures need to stand a 32-byte constant in for a real
 * derivation without booting a keyring. A production call site naming it is a review failure, not a
 * style question.
 *
 * ## On holding one
 *
 * [value] is an immutable `String` and cannot be wiped, exactly like the `String` this replaced. Hold
 * it for as short a time as possible; never log it, persist it, or cache it. [toString] is overridden
 * so an interpolated instance cannot leak the password into a log line by accident — reaching [value]
 * has to be deliberate.
 */
@JvmInline
value class IdentityStorePassword private constructor(val value: String) {

    /** Redacted on purpose: `"$storePassword"` must not be a way to print a device secret. */
    override fun toString(): String = "IdentityStorePassword(redacted)"

    companion object {
        /**
         * The one production constructor, deliberately `internal` to `data:crypto` so that the only
         * way across the module boundary is [VaultCipher.identityStorePassword].
         */
        internal fun ofDerived(value: String): IdentityStorePassword {
            require(value.isNotEmpty()) { "the derived identity-store password must not be empty" }
            return IdentityStorePassword(value)
        }

        /**
         * **Not derived from anything.** Test fixtures only.
         *
         * Named to be impossible to reach for by accident and trivial to grep for. Every use of this
         * outside a test source set is a low-PBE store sealed with a password that may be guessable,
         * which is the failure this type exists to make visible.
         */
        fun unsafeNotFromKeyring(value: String): IdentityStorePassword = IdentityStorePassword(value)
    }
}
