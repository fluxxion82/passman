package ai.passman.crypto.keyring

import ai.passman.crypto.kdf.JvmPasswordHasher
import ai.passman.crypto.vault.VaultFailure
import ai.passman.domain.user.models.KdfParams
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The device keyring: a single small file holding the 32-byte **Device Master Key** (DMK) wrapped by
 * Argon2id over the login password. Every other local secret — the vault root key, the `hybrid.key`
 * and `mldsa.key` file keys, and the PKCS#12 store password — is derived from the DMK through
 * [KeyringSubkeys], so the login password gates all of them behind exactly one memory-hard
 * derivation and a password change rewraps this file and nothing else.
 *
 * At-rest layout (`<localPath>/keystore/<user>/keyring.pmk`):
 * ```
 *   magic "PMKR"(4) | version(1)=1 | kdfId(1)=1 (argon2id v1.3) |
 *   timeCost(4,BE) | memoryKiB(4,BE) | parallelism(4,BE) |
 *   saltLen(1)=48 | salt(48) |
 *   wrapNonce(12) | wrappedDmk(32 + 16 tag)
 * ```
 * The entire header — every byte before `wrappedDmk`, including the declared cost parameters and the
 * nonce — is bound as AES-256-GCM associated data, so downgrading the work factor or substituting a
 * salt fails authentication rather than silently producing a different key. The wrapping key is
 * `Argon2id(password, salt, params)` and is never stored.
 *
 * The DMK returned by [create] and [unwrap] belongs to the caller: this object wipes the derived
 * wrapping key and its own intermediate copies on every path, but the session owns the DMK's
 * lifetime. That wipe is best-effort in exactly the sense `HybridKem.wipe` documents — `SecretKeySpec`
 * clones the key into an array it never wipes and does not override `destroy()`, and the JCE's own
 * internal buffers are outside this object's control — so it shrinks the exposure window rather than
 * closing it. Closing it would need native memory management this layer does not have.
 */
object KeyringEnvelope {

    class Created(val bytes: ByteArray, val dmk: ByteArray)

    private val MAGIC = byteArrayOf(0x50, 0x4D, 0x4B, 0x52) // "PMKR"
    private const val VERSION: Byte = 1

    /** The only KDF this version defines: Argon2id, version 1.3. */
    private const val KDF_ID_ARGON2ID_V13: Byte = 1

    internal const val VERSION_OFFSET = 4
    internal const val KDF_ID_OFFSET = 5
    internal const val TIME_COST_OFFSET = 6
    internal const val MEMORY_KIB_OFFSET = 10
    internal const val PARALLELISM_OFFSET = 14
    internal const val SALT_LEN_OFFSET = 18
    internal const val SALT_OFFSET = 19

    internal const val SALT_BYTES = 48
    internal const val GCM_NONCE_BYTES = 12
    internal const val DMK_BYTES = 32
    private const val GCM_TAG_BYTES = 16
    private const val GCM_TAG_BITS = 128

    /** Everything the AEAD binds as associated data. */
    internal const val NONCE_OFFSET = SALT_OFFSET + SALT_BYTES
    internal const val HEADER_BYTES = NONCE_OFFSET + GCM_NONCE_BYTES
    internal const val WRAPPED_DMK_OFFSET = HEADER_BYTES
    internal const val FILE_BYTES = WRAPPED_DMK_OFFSET + DMK_BYTES + GCM_TAG_BYTES

    /**
     * Cost ceilings are this object's own concern, not the hasher's. [unwrap] reads its parameters
     * from a file an attacker can rewrite, and Argon2BytesGenerator honours whatever memory cost it
     * is handed — an unbounded header would take the process down before any tag check ran.
     * The floors, by contrast, are shared with [JvmPasswordHasher] so the two can never drift.
     *
     * The memory ceiling is sized against the *smallest* heap this code runs on, not against a
     * desktop's. Android gives a process somewhere around 128-512 MB, so a ceiling above that would
     * still let a tampered header OOM the app before authentication — the exact failure it exists to
     * prevent. 256 MiB is the largest value that stays inside a typical Android heap while leaving 4x
     * headroom over the 64 MiB production default, so a future cost increase does not need a format
     * change.
     */
    internal const val MAX_ARGON2_MEMORY_KIB = 1 shl 18 // 256 MiB
    internal const val MAX_ARGON2_ITERATIONS = 64
    internal const val MAX_ARGON2_PARALLELISM = 16

    /** Argon2id output length. Not stored in the file, so both directions pin it here. */
    private const val WRAP_KEY_BYTES = 32

    /** What production wraps new keyrings under. */
    internal val DEFAULT_PARAMS: KdfParams = KdfParams.ARGON2ID_DEFAULT

    private val secureRandom = SecureRandom()
    private val hasher = JvmPasswordHasher()

    /** Generate a brand-new random DMK and seal it under [password]. */
    fun create(password: String, params: KdfParams = DEFAULT_PARAMS): Created {
        // Reject the parameter set *before* drawing key material. Rejecting afterwards would leave a
        // live 32-byte random key on the heap with no owner to wipe it, since nothing is returned.
        val sealedParams = validated(params)
        val dmk = ByteArray(DMK_BYTES).also { secureRandom.nextBytes(it) }
        return Created(seal(dmk, password, sealedParams), dmk)
    }

    /**
     * Re-seal an already-unwrapped [dmk] under [newPassword]. This is the whole of a password
     * change: the DMK does not rotate, so nothing else on disk has to be rewritten.
     */
    fun rewrap(dmk: ByteArray, newPassword: String, params: KdfParams = DEFAULT_PARAMS): ByteArray {
        require(dmk.size == DMK_BYTES) { "device master key must be $DMK_BYTES bytes, was ${dmk.size}" }
        return seal(dmk, newPassword, params)
    }

    /**
     * @throws VaultFailure.Malformed if the file cannot be read as a keyring at all — this is decided
     *   entirely before any derivation runs, so a rewritten header can neither pick the work factor
     *   nor stall the process.
     * @throws VaultFailure.WrongPassword if the AEAD tag does not verify. That is the same event for
     *   a mistyped password and for a tampered-but-structurally-valid file; see [VaultFailure] for why
     *   this reports the recoverable one rather than pretending to tell them apart.
     */
    fun unwrap(bytes: ByteArray, password: String): ByteArray {
        // Validate the fixed prefix before reading anything out of it, then pin the total length.
        // Every offset below is inside that length, so no slice can run off the end of a short file.
        malformedUnless(bytes.size > SALT_LEN_OFFSET) { "truncated keyring: ${bytes.size} bytes" }
        malformedUnless(
            bytes[0] == MAGIC[0] && bytes[1] == MAGIC[1] && bytes[2] == MAGIC[2] && bytes[3] == MAGIC[3],
        ) { "not a keyring file" }
        malformedUnless(bytes[VERSION_OFFSET] == VERSION) {
            "unsupported keyring version: ${bytes[VERSION_OFFSET]}"
        }
        malformedUnless(bytes[KDF_ID_OFFSET] == KDF_ID_ARGON2ID_V13) {
            "unsupported keyring kdfId: ${bytes[KDF_ID_OFFSET]}"
        }
        val saltLength = bytes[SALT_LEN_OFFSET].toInt() and 0xFF
        malformedUnless(saltLength == SALT_BYTES) { "unsupported keyring salt length: $saltLength" }
        malformedUnless(bytes.size == FILE_BYTES) {
            "keyring must be exactly $FILE_BYTES bytes, was ${bytes.size}"
        }

        val params = KdfParams(
            algorithm = KdfParams.ARGON2ID,
            keyLengthBytes = WRAP_KEY_BYTES,
            iterations = readInt(bytes, TIME_COST_OFFSET),
            memoryKib = readInt(bytes, MEMORY_KIB_OFFSET),
            parallelism = readInt(bytes, PARALLELISM_OFFSET),
        )
        // Before any derivation: a tampered header must never choose the work factor.
        costViolation(params)?.let { throw VaultFailure.Malformed(it) }

        val salt = bytes.copyOfRange(SALT_OFFSET, SALT_OFFSET + SALT_BYTES)
        val nonce = bytes.copyOfRange(NONCE_OFFSET, NONCE_OFFSET + GCM_NONCE_BYTES)
        val header = bytes.copyOfRange(0, HEADER_BYTES)
        val wrappedDmk = bytes.copyOfRange(WRAPPED_DMK_OFFSET, FILE_BYTES)

        var wrapKey: ByteArray? = null
        try {
            wrapKey = hasher.derive(password, salt, params)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(header)
            }
            val dmk = try {
                cipher.doFinal(wrappedDmk)
            } catch (e: GeneralSecurityException) {
                // AEADBadTagException: a wrong password, a tampered header, or a tampered ciphertext.
                throw VaultFailure.WrongPassword(e)
            }
            if (dmk.size != DMK_BYTES) {
                dmk.fill(0)
                throw VaultFailure.Malformed("keyring holds a $DMK_BYTES-byte key, found ${dmk.size}")
            }
            return dmk
        } finally {
            wrapKey?.fill(0)
        }
    }

    /**
     * Both entry points funnel through here so neither can forget to draw fresh randomness: reusing
     * a salt across a password change would let the two files be attacked as one, and reusing a
     * nonce under the same derived key is an outright key-recovery break of GCM.
     */
    private fun seal(dmk: ByteArray, password: String, params: KdfParams): ByteArray {
        // Idempotent: [create] has already validated, but [rewrap] and any future caller have not.
        val sealed = validated(params)

        val salt = ByteArray(SALT_BYTES).also { secureRandom.nextBytes(it) }
        val nonce = ByteArray(GCM_NONCE_BYTES).also { secureRandom.nextBytes(it) }
        val header = buildHeader(sealed, salt, nonce)

        var wrapKey: ByteArray? = null
        try {
            wrapKey = hasher.derive(password, salt, sealed)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
                updateAAD(header)
            }
            return header + cipher.doFinal(dmk)
        } finally {
            wrapKey?.fill(0)
        }
    }

    private fun buildHeader(params: KdfParams, salt: ByteArray, nonce: ByteArray): ByteArray {
        val header = ByteArray(HEADER_BYTES)
        MAGIC.copyInto(header, 0)
        header[VERSION_OFFSET] = VERSION
        header[KDF_ID_OFFSET] = KDF_ID_ARGON2ID_V13
        writeInt(header, TIME_COST_OFFSET, params.iterations)
        writeInt(header, MEMORY_KIB_OFFSET, params.memoryKib)
        writeInt(header, PARALLELISM_OFFSET, params.parallelism)
        header[SALT_LEN_OFFSET] = SALT_BYTES.toByte()
        salt.copyInto(header, SALT_OFFSET)
        nonce.copyInto(header, NONCE_OFFSET)
        return header
    }

    /** Pins the algorithm and the output length, then range-checks the costs. */
    private fun validated(params: KdfParams): KdfParams {
        require(params.algorithm == KdfParams.ARGON2ID) {
            "the keyring is argon2id-only, got: ${params.algorithm}"
        }
        return params.copy(keyLengthBytes = WRAP_KEY_BYTES).also { validateCosts(it) }
    }

    /**
     * The cost bounds are shared by both directions but the *failure* differs by who supplied the
     * parameters: [create] and [rewrap] are handed them by this codebase, so a bad set is a
     * programming error ([IllegalArgumentException]); [unwrap] reads them out of a file an attacker
     * can rewrite, so a bad set is a damaged artifact ([VaultFailure.Malformed]). One predicate,
     * two throw sites — the bounds themselves can never drift between the two.
     */
    private fun validateCosts(params: KdfParams) {
        costViolation(params)?.let { throw IllegalArgumentException(it) }
    }

    private fun costViolation(params: KdfParams): String? = when {
        params.memoryKib !in JvmPasswordHasher.MIN_ARGON2_MEMORY_KIB..MAX_ARGON2_MEMORY_KIB ->
            "keyring argon2id memory cost out of range: ${params.memoryKib}"
        params.iterations !in JvmPasswordHasher.MIN_ARGON2_ITERATIONS..MAX_ARGON2_ITERATIONS ->
            "keyring argon2id time cost out of range: ${params.iterations}"
        params.parallelism !in 1..MAX_ARGON2_PARALLELISM ->
            "keyring argon2id parallelism out of range: ${params.parallelism}"
        else -> null
    }

    private inline fun malformedUnless(condition: Boolean, message: () -> String) {
        if (!condition) throw VaultFailure.Malformed(message())
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = ((value ushr 24) and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 3] = (value and 0xFF).toByte()
    }
}
