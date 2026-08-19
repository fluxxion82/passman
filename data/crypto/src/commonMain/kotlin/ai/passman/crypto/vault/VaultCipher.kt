package ai.passman.crypto.vault

import ai.passman.crypto.CryptoKey

/**
 * The vault's at-rest boundary: one login-password gate (the device keyring) and one symmetric
 * envelope (suite 5) for the database itself.
 *
 * This interface is in `commonMain` because the repositories that call it are, and those compile for
 * iOS. iOS simply registers no binding for now, exactly as it already does for the other platform
 * services — the contract exists so the shared repositories can be written once.
 *
 * The password appears in exactly two places in this API, [unlockSession] and [createSession], and it
 * is used for exactly one thing: the Argon2id derivation inside the keyring. The vault envelope
 * itself contains no KDF parameters and never sees the password. That is the whole point — one
 * memory-hard derivation per login gates every local secret, and a password change rewraps the
 * keyring and nothing else.
 */
interface VaultCipher {

    /**
     * Unlock the keyring, returning the in-session DMK holder.
     *
     * @throws VaultFailure.WrongPassword if the password does not unwrap the keyring.
     * @throws VaultFailure.Malformed if the keyring file itself cannot be parsed.
     */
    fun unlockSession(keyringBytes: ByteArray, password: String): VaultSessionKey

    /** Create a brand-new keyring for a new account, with a fresh random DMK. */
    fun createSession(password: String): CreatedSession

    /**
     * Rewrap the same DMK under [newPassword]; returns new keyring bytes. Nothing else on disk
     * changes, because every other secret hangs off the DMK and the DMK does not rotate.
     */
    fun rewrapSession(sessionKey: VaultSessionKey, newPassword: String): ByteArray

    /**
     * The password protecting this account's PKCS#12 identity store, derived from the session's
     * device master key.
     *
     * This exists on the interface rather than as a direct `KeyringSubkeys` call because the key
     * material inside [VaultSessionKey] is deliberately unreachable outside `data:crypto`, and the
     * repositories that create and open the identity store are in another module. The interface is
     * the boundary; an [IdentityStorePassword] crosses it, the DMK never does.
     *
     * Bouncy Castle's PKCS#12 PBE is SHA-1-based and not memory-hard, which is exactly why this must
     * be a derived 256-bit value and never the login password: an attacker holding the data directory
     * would otherwise attack the cheap KDF on the `.pfx` instead of the Argon2id on the keyring.
     *
     * **This call is the only production source of an [IdentityStorePassword]**, and that is the
     * point: the identity store is written at a negligible PKCS#12 work factor, which is sound only
     * for a password nobody can guess. See [IdentityStorePassword].
     *
     * Deterministic for a given DMK, so it also serves as a DMK-equality oracle — comparing two
     * sessions' values proves a rewrap preserved the key without ever exposing it.
     *
     * The wrapped `String` is immutable and cannot be wiped. Hold it for as short a time as
     * possible and never log, persist or cache it.
     */
    fun identityStorePassword(sessionKey: VaultSessionKey): IdentityStorePassword

    /** Seal [plaintext] as a suite-5 vault envelope. Always suite 5; never RSA, never a legacy suite. */
    fun encryptVault(plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray

    /**
     * Open a vault envelope of any generation.
     *
     * [legacyPrivateKey] is consulted only for v1/v2 envelopes and is resolved lazily, so a migrated
     * vault never touches the PKCS#12 store. A non-null parameter would force every caller to open
     * that store even on the pure-v5 path, which is exactly the cost this design removes.
     *
     * Every failure of this call is a [VaultFailure]. That is a hard requirement of this boundary, not
     * a convenience: the implementations live on JVM/Android and the callers are `commonMain`
     * repositories that compile for iOS, where `javax.crypto.AEADBadTagException` and
     * `kotlinx.serialization`'s decoding exceptions cannot be named in a `catch` clause at all. An
     * implementation that lets a platform exception through leaves the caller with `catch (e:
     * Exception)` or an uncaught crash, and the crash lands on the migration read — the riskiest read
     * in the product.
     *
     * @throws VaultFailure.Tampered if the envelope's structure parses but its contents do not
     *   authenticate: a suite-5 envelope that fails under [sessionKey], or a legacy envelope that
     *   fails under the key [legacyPrivateKey] yields (which includes supplying the wrong account's
     *   legacy key — see [VaultFailure.Tampered], the vault may well be intact).
     * @throws VaultFailure.Malformed if the bytes are not a readable envelope at all: a truncated or
     *   shredded file, a suite no build of this reader supports, or a legacy envelope for which
     *   [legacyPrivateKey] yields `null` (that one, and only that one, sets
     *   [VaultFailure.Malformed.legacyKeyUnavailable]).
     */
    fun decryptVault(
        ciphertext: ByteArray,
        sessionKey: VaultSessionKey,
        legacyPrivateKey: () -> CryptoKey?,
    ): UnlockedVault
}

class CreatedSession(val keyringBytes: ByteArray, val sessionKey: VaultSessionKey)

/**
 * @property needsMigration true when the bytes were read through the legacy RSA path, so the caller
 *   should rewrite the vault as suite 5 once it has safely persisted the recovered plaintext.
 */
class UnlockedVault(val plaintext: ByteArray, val needsMigration: Boolean)
