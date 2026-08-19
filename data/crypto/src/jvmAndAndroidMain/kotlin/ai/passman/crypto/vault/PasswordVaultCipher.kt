package ai.passman.crypto.vault

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.keyring.KeyringEnvelope
import ai.passman.crypto.keyring.KeyringSubkeys
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * JVM/Android [VaultCipher]: suite-5 vault envelopes plus the keyring operations that gate them.
 *
 * At-rest layout (suite 5; suites 2, 3 and 4 belong to `EnvelopeCodec` and are not reused):
 * ```
 *   magic "PMNV"(4) | version(1)=1 | suite(1)=5 |
 *   rootWrapNonce(12) | wrappedRootKey(32 + 16 tag) |
 *   payloadNonce(12) | ciphertext+tag
 * ```
 *
 * **No KDF parameters appear anywhere in this file.** The only password derivation in the system is
 * the Argon2id inside [KeyringEnvelope]; the vault root key is 32 random bytes per write, wrapped
 * under `KeyringSubkeys.vaultWrapKey(dmk)`. A password change therefore rewraps the keyring and
 * leaves every vault byte untouched.
 *
 * **AAD.** Each of the two ciphers binds the entire contiguous run of header bytes in front of its
 * own ciphertext: [ROOT_WRAP_AAD_BYTES] (magic, version, suite, root-wrap nonce) for the root wrap,
 * and all [HEADER_BYTES] (those plus the wrapped root key and the payload nonce) for the payload.
 * The root wrap cannot bind the full header, because the wrapped root key it would be binding is its
 * own output — the plan's "bind the full header on both ciphers" is circular read literally. Between
 * the two tags every header byte is still covered, so no single-byte edit anywhere in the header
 * survives, which is the property that phrasing was after. This is the same "everything before this
 * ciphertext" idiom `CryptoEnvelope` and [KeyringEnvelope] already use.
 *
 * Anything that is not a suite-5 envelope is handed to [CryptoService], which reads the legacy v1
 * JSON blobs and v2 RSA-OAEP envelopes, and the result is flagged [UnlockedVault.needsMigration].
 *
 * **Failures are always [VaultFailure].** Nothing this class calls — not the JCE, not the legacy
 * [CryptoService] and its JSON parser — is allowed to throw through it, because its interface lives in
 * `commonMain` where those types cannot be caught by name. The legacy path is the one that matters:
 * it is what Task 5 runs on every migration read, so an untranslated `AEADBadTagException` there is a
 * crash on a damaged or mispaired vault.
 *
 * **Wiping is best-effort**, in the same sense [KeyringEnvelope] and [VaultSessionKey] document. The
 * arrays this class owns — the vault root, the derived wrap key — are zeroed in `finally` on every
 * path, but `SecretKeySpec` clones whatever it is handed into an array it never wipes and does not
 * override `destroy()`, and the JCE's own buffers are out of reach. That shrinks the window; it does
 * not close it. Closing it needs native memory management this layer does not have.
 */
class PasswordVaultCipher(
    private val cryptoService: CryptoService = JvmCryptoService(),
) : VaultCipher {

    override fun unlockSession(keyringBytes: ByteArray, password: String): VaultSessionKey =
        VaultSessionKey(KeyringEnvelope.unwrap(keyringBytes, password))

    override fun createSession(password: String): CreatedSession {
        val created = KeyringEnvelope.create(password)
        return CreatedSession(created.bytes, VaultSessionKey(created.dmk))
    }

    override fun rewrapSession(sessionKey: VaultSessionKey, newPassword: String): ByteArray =
        KeyringEnvelope.rewrap(sessionKey.material(), newPassword)

    override fun identityStorePassword(sessionKey: VaultSessionKey): IdentityStorePassword =
        IdentityStorePassword.ofDerived(KeyringSubkeys.pkcs12Password(sessionKey.material()))

    override fun encryptVault(plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray {
        val dmk = sessionKey.material()
        var vaultWrapKey: ByteArray? = null
        var root: ByteArray? = null
        try {
            vaultWrapKey = KeyringSubkeys.vaultWrapKey(dmk)
            root = ByteArray(VAULT_ROOT_BYTES).also { secureRandom.nextBytes(it) }

            // Two independent nonces: one per key. Reusing a single nonce under two different keys
            // would be harmless in isolation but is exactly the kind of shortcut that stops being
            // harmless the moment one of those keys is reused, so the format keeps them separate.
            val rootWrapNonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }
            val payloadNonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }

            val prefix = ByteArray(ROOT_WRAP_AAD_BYTES)
            MAGIC.copyInto(prefix, 0)
            prefix[VERSION_OFFSET] = VERSION
            prefix[SUITE_OFFSET] = SUITE_VAULT
            rootWrapNonce.copyInto(prefix, ROOT_WRAP_NONCE_OFFSET)

            val wrappedRoot = gcm(Cipher.ENCRYPT_MODE, vaultWrapKey, rootWrapNonce, prefix, root)

            val header = ByteArray(HEADER_BYTES)
            prefix.copyInto(header, 0)
            wrappedRoot.copyInto(header, WRAPPED_ROOT_KEY_OFFSET)
            payloadNonce.copyInto(header, PAYLOAD_NONCE_OFFSET)

            return header + gcm(Cipher.ENCRYPT_MODE, root, payloadNonce, header, plaintext)
        } finally {
            root?.fill(0)
            vaultWrapKey?.fill(0)
        }
    }

    override fun decryptVault(
        ciphertext: ByteArray,
        sessionKey: VaultSessionKey,
        legacyPrivateKey: () -> CryptoKey?,
    ): UnlockedVault {
        // Suite detection first, and only then — if this is not a suite-5 vault — is the provider
        // invoked. That ordering is the whole reason it is a provider: a migrated account must never
        // open the PKCS#12 identity store just to read its own vault.
        if (!looksLikeSuiteFive(ciphertext)) return decryptLegacy(ciphertext, legacyPrivateKey)

        if (ciphertext[VERSION_OFFSET] != VERSION) {
            throw VaultFailure.Malformed("unsupported vault version: ${ciphertext[VERSION_OFFSET]}")
        }
        if (ciphertext.size < MIN_ENVELOPE_BYTES) {
            throw VaultFailure.Malformed(
                "truncated vault envelope: ${ciphertext.size} bytes, minimum $MIN_ENVELOPE_BYTES",
            )
        }

        val dmk = sessionKey.material()
        var vaultWrapKey: ByteArray? = null
        var root: ByteArray? = null
        try {
            vaultWrapKey = KeyringSubkeys.vaultWrapKey(dmk)
            val prefix = ciphertext.copyOfRange(0, ROOT_WRAP_AAD_BYTES)
            val header = ciphertext.copyOfRange(0, HEADER_BYTES)

            root = try {
                gcm(
                    mode = Cipher.DECRYPT_MODE,
                    key = vaultWrapKey,
                    nonce = ciphertext.copyOfRange(ROOT_WRAP_NONCE_OFFSET, WRAPPED_ROOT_KEY_OFFSET),
                    aad = prefix,
                    input = ciphertext.copyOfRange(WRAPPED_ROOT_KEY_OFFSET, PAYLOAD_NONCE_OFFSET),
                )
            } catch (e: GeneralSecurityException) {
                // The session key was already authenticated by the keyring unwrap, so this is never a
                // password problem: either the file changed or the wrong account's key was supplied.
                throw VaultFailure.Tampered("the vault root key failed authentication", e)
            }
            if (root.size != VAULT_ROOT_BYTES) {
                throw VaultFailure.Malformed("vault root key is ${root.size} bytes, expected $VAULT_ROOT_BYTES")
            }

            val plaintext = try {
                gcm(
                    mode = Cipher.DECRYPT_MODE,
                    key = root,
                    nonce = ciphertext.copyOfRange(PAYLOAD_NONCE_OFFSET, PAYLOAD_OFFSET),
                    aad = header,
                    input = ciphertext.copyOfRange(PAYLOAD_OFFSET, ciphertext.size),
                )
            } catch (e: GeneralSecurityException) {
                throw VaultFailure.Tampered("the vault payload failed authentication", e)
            }
            return UnlockedVault(plaintext, needsMigration = false)
        } finally {
            root?.fill(0)
            vaultWrapKey?.fill(0)
        }
    }

    /**
     * Everything that is not suite 5: the legacy v1 JSON blobs and v2 RSA-OAEP envelopes the
     * [CryptoService] path still reads — and nothing else.
     *
     * Every exit is a [VaultFailure]. `CryptoService.decryptBytes` throws three different untyped
     * things at this boundary, all of them reachable in production and none of them nameable from
     * `commonMain`: `AEADBadTagException` for a corrupt v2 envelope, `BadPaddingException` for the
     * wrong legacy RSA key, and `JsonDecodingException` for a file that is not a legacy envelope at
     * all. Task 5 runs this on every migration read, so leaving any of them untranslated means a
     * corrupt or mispaired legacy vault crashes the migration.
     */
    private fun decryptLegacy(ciphertext: ByteArray, legacyPrivateKey: () -> CryptoKey?): UnlockedVault {
        // A "PMNV" header carrying version 1 and a suite this build does not know is a *forward*
        // vault written by a newer build, not a legacy one. Handing it to the RSA reader would report
        // "no legacy key is available", sending the user after a .pfx that has nothing to do with the
        // problem. Suite 2 is the only suite the legacy reader genuinely owns; suites 3 and 4 are
        // EnvelopeCodec's wire formats and were never written to a vault file, so they are as
        // unreadable here as suite 6 would be. (A magic-carrying header with an unknown *version*
        // still falls through to the legacy reader, which now returns a typed Malformed rather than
        // crashing; no build has ever written such a file, so the extra precision is not worth a
        // second bespoke branch.)
        unsupportedVaultSuite(ciphertext)?.let {
            throw VaultFailure.Malformed("unsupported vault suite: $it")
        }

        // Outside the try on purpose: whatever the caller's provider throws is the caller's own
        // failure to open the PKCS#12 store, not a statement about these bytes.
        val legacy = legacyPrivateKey()
            ?: throw VaultFailure.Malformed(
                "not a suite-$SUITE_VAULT vault envelope and no legacy key is available to read it",
                legacyKeyUnavailable = true,
            )

        return try {
            UnlockedVault(cryptoService.decryptBytes(ciphertext, legacy), needsMigration = true)
        } catch (e: GeneralSecurityException) {
            // The structure parsed and a key was applied to it, so this is the legacy path's exact
            // analogue of the suite-5 tag failures in [decryptVault]: either the file changed or it
            // was paired with another account's identity — and in the second case the vault itself is
            // intact, which is why VaultFailure.Tampered no longer says "restore a backup" and this
            // message does not either. The JCE's message here is a fixed string ("Tag
            // mismatch!", "Decryption error") that carries no file content, so keeping the cause is
            // safe and preserves the stack trace.
            throw VaultFailure.Tampered("the legacy vault envelope failed authentication", e)
        } catch (e: Exception) {
            // Not an envelope at all: JSON that does not parse, a truncated v2 header, a bad wrapped-
            // key length. The cause is deliberately dropped and none of its text is reused —
            // JsonDecodingException's message embeds the input it failed on, which here is raw vault
            // file content, and anything attached as `cause` is printed by every stack trace and by
            // any logger handed the exception. A crash report must not carry vault bytes. `e` is
            // therefore referenced only for its type; use a debugger, not a log, to see it.
            throw VaultFailure.Malformed("not a readable vault envelope")
        }
    }

    private fun looksLikeSuiteFive(bytes: ByteArray): Boolean =
        hasVaultMagic(bytes) && bytes[SUITE_OFFSET] == SUITE_VAULT

    /**
     * The suite byte of a version-1 "PMNV" header that neither this reader nor the legacy reader
     * supports, or `null` when the bytes are not such a header ([CryptoService] gets those: legacy v1
     * JSON has no magic at all) or carry [SUITE_LEGACY_RSA], which the legacy reader owns.
     */
    private fun unsupportedVaultSuite(bytes: ByteArray): Byte? {
        if (!hasVaultMagic(bytes) || bytes[VERSION_OFFSET] != VERSION) return null
        val suite = bytes[SUITE_OFFSET]
        return if (suite == SUITE_LEGACY_RSA) null else suite
    }

    /** True when [bytes] is long enough to carry a suite byte and starts with the "PMNV" magic. */
    private fun hasVaultMagic(bytes: ByteArray): Boolean =
        bytes.size > SUITE_OFFSET &&
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3]

    private fun gcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        updateAAD(aad)
    }.doFinal(input)

    internal companion object {
        private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4E, 0x56) // "PMNV"
        private const val VERSION: Byte = 1

        /** Suites 2 (RSA-OAEP+GCM), 3 (hybrid) and 4 (signed hybrid) belong to `EnvelopeCodec`. */
        const val SUITE_VAULT: Byte = 5

        /**
         * The one non-vault suite this reader dispatches instead of rejecting: every RSA-era vault on
         * disk is suite 2, and [CryptoService] still reads it. Suites 3 and 4 are wire formats and
         * were never written to a vault file.
         */
        const val SUITE_LEGACY_RSA: Byte = 2

        const val VERSION_OFFSET = 4
        const val SUITE_OFFSET = 5
        const val ROOT_WRAP_NONCE_OFFSET = 6

        const val GCM_NONCE_BYTES = 12
        const val VAULT_ROOT_BYTES = 32
        private const val GCM_TAG_BYTES = 16
        private const val GCM_TAG_BITS = 128

        const val WRAPPED_ROOT_KEY_OFFSET = ROOT_WRAP_NONCE_OFFSET + GCM_NONCE_BYTES
        const val PAYLOAD_NONCE_OFFSET = WRAPPED_ROOT_KEY_OFFSET + VAULT_ROOT_BYTES + GCM_TAG_BYTES
        const val PAYLOAD_OFFSET = PAYLOAD_NONCE_OFFSET + GCM_NONCE_BYTES

        /** Everything the payload cipher binds as associated data. */
        const val HEADER_BYTES = PAYLOAD_OFFSET

        /** Everything the root-wrap cipher binds: the header bytes that exist before it runs. */
        const val ROOT_WRAP_AAD_BYTES = WRAPPED_ROOT_KEY_OFFSET

        /** A vault holding an empty database is still a full header plus the payload's tag. */
        const val MIN_ENVELOPE_BYTES = HEADER_BYTES + GCM_TAG_BYTES

        private val secureRandom = SecureRandom()
    }
}
