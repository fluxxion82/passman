package ai.passman.crypto.keyring

import ai.passman.crypto.kdf.JvmPasswordHasher
import ai.passman.crypto.vault.VaultFailure
import ai.passman.domain.user.models.KdfParams
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The parameter set here is deliberately the OWASP minimum (19 MiB / t=2), not the production
 * [KdfParams.ARGON2ID_DEFAULT] 64 MiB / t=3 — this suite derives dozens of times and the cost floor
 * is the only property that matters for these assertions. That production picks the stronger set is
 * asserted once, as metadata, in [defaultParamsAreTheProductionArgon2idParams].
 *
 * Two rules this file must keep:
 *
 * 1. **No `assertFails`.** It wraps `runCatching`, which catches `Throwable`, so an `OutOfMemoryError`
 *    from an unbounded Argon2 cost would read as a pass and a deleted ceiling would look tested. Every
 *    rejection asserts the *specific* type it should get: [VaultFailure.Malformed] for a file the
 *    envelope refuses to act on, [VaultFailure.WrongPassword] for an AEAD tag that should not verify,
 *    and plain [IllegalArgumentException] for the two cases that are caller misuse rather than a bad
 *    artifact ([KeyringEnvelope.create] with a non-Argon2id parameter set, [KeyringEnvelope.rewrap]
 *    with a wrong-length key). Those three distinctions are the whole reason the hierarchy exists, so
 *    asserting the base type everywhere would test nothing.
 * 2. **Layout assertions use literal numbers.** Reading the header through the same constants that
 *    wrote it makes swapping two offsets invisible while the on-disk format silently changes; an iOS
 *    port would then be written against a spec this suite no longer enforces.
 */
class KeyringEnvelopeTest {

    @Test
    fun roundTripsTheDeviceMasterKey() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        assertEquals(32, file.dmk.size, "DMK is 256 bits")
        assertEquals(KeyringEnvelope.FILE_BYTES, file.bytes.size)
        assertContentEquals(file.dmk, KeyringEnvelope.unwrap(file.bytes, PASSWORD))
    }

    @Test
    fun headerMatchesTheSpecifiedLayout() {
        // Every offset below is a literal from the plan's "Crypto formats" section, never a constant
        // from the class under test. Swapping two offsets in KeyringEnvelope must fail here.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        assertEquals(127, bytes.size, "4+1+1+4+4+4+1+48+12+32+16")
        assertContentEquals("PMKR".encodeToByteArray(), bytes.copyOfRange(0, 4), "magic")
        assertEquals(1, bytes[4].toInt(), "version")
        assertEquals(1, bytes[5].toInt(), "kdfId = argon2id v1.3")
        assertEquals(TEST_PARAMS.iterations, readInt(bytes, 6), "timeCost(4,BE) at 6")
        assertEquals(TEST_PARAMS.memoryKib, readInt(bytes, 10), "memoryKiB(4,BE) at 10")
        assertEquals(TEST_PARAMS.parallelism, readInt(bytes, 14), "parallelism(4,BE) at 14")
        assertEquals(48, bytes[18].toInt(), "saltLen at 18")
        assertEquals(48 + 12 + 32 + 16, bytes.size - 19, "salt|nonce|dmk+tag follow at 19")
    }

    @Test
    fun offsetConstantsMatchTheSpecifiedLayout() {
        // The constants are the API the rest of the codebase and the future iOS port read the format
        // through, so they are pinned to their spec values independently of any round trip.
        assertEquals(4, KeyringEnvelope.VERSION_OFFSET)
        assertEquals(5, KeyringEnvelope.KDF_ID_OFFSET)
        assertEquals(6, KeyringEnvelope.TIME_COST_OFFSET)
        assertEquals(10, KeyringEnvelope.MEMORY_KIB_OFFSET)
        assertEquals(14, KeyringEnvelope.PARALLELISM_OFFSET)
        assertEquals(18, KeyringEnvelope.SALT_LEN_OFFSET)
        assertEquals(19, KeyringEnvelope.SALT_OFFSET)
        assertEquals(48, KeyringEnvelope.SALT_BYTES)
        assertEquals(67, KeyringEnvelope.NONCE_OFFSET)
        assertEquals(12, KeyringEnvelope.GCM_NONCE_BYTES)
        assertEquals(79, KeyringEnvelope.HEADER_BYTES)
        assertEquals(79, KeyringEnvelope.WRAPPED_DMK_OFFSET)
        assertEquals(32, KeyringEnvelope.DMK_BYTES)
        assertEquals(127, KeyringEnvelope.FILE_BYTES)
    }

    @Test
    fun unwrapsTheGoldenVector() {
        // Format lock, matching the standard the HKDF labels are held to in KeyringSubkeysTest. These
        // bytes were produced once from a fixed salt (00..2f), a fixed nonce (a0..ab) and a fixed DMK
        // under Argon2id t=2 / m=19456 / p=1. Any change to the field order, the big-endian encoding,
        // the salt or nonce position, the AAD extent, or the Argon2id parameterisation breaks this and
        // nothing else in the suite would notice.
        val dmk = KeyringEnvelope.unwrap(hex(GOLDEN_FILE), GOLDEN_PASSWORD)
        assertContentEquals(hex(GOLDEN_DMK), dmk)
    }

    @Test
    fun goldenVectorCarriesTheSpecifiedHeaderBytes() {
        val bytes = hex(GOLDEN_FILE)
        assertEquals(127, bytes.size)
        assertContentEquals("PMKR".encodeToByteArray(), bytes.copyOfRange(0, 4))
        assertEquals(1, bytes[4].toInt())
        assertEquals(1, bytes[5].toInt())
        assertEquals(2, readInt(bytes, 6), "timeCost")
        assertEquals(19_456, readInt(bytes, 10), "memoryKiB")
        assertEquals(1, readInt(bytes, 14), "parallelism")
        assertEquals(48, bytes[18].toInt(), "saltLen")
        assertContentEquals(ByteArray(48) { it.toByte() }, bytes.copyOfRange(19, 67), "salt")
        assertContentEquals(ByteArray(12) { (0xA0 + it).toByte() }, bytes.copyOfRange(67, 79), "nonce")
    }

    @Test
    fun defaultParamsAreTheProductionArgon2idParams() {
        // Metadata assertion: production must select the 64 MiB / t=3 set, not this suite's cheap one.
        assertEquals(KdfParams.ARGON2ID_DEFAULT, KeyringEnvelope.DEFAULT_PARAMS)
    }

    @Test
    fun everyCreateDrawsAFreshSaltNonceAndKey() {
        val a = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        val b = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        assertFalse(salt(a.bytes).contentEquals(salt(b.bytes)), "salt must be fresh per keyring")
        assertFalse(nonce(a.bytes).contentEquals(nonce(b.bytes)), "nonce must be fresh per keyring")
        assertFalse(a.dmk.contentEquals(b.dmk), "DMK must be fresh per keyring")
    }

    @Test
    fun wrongPasswordFails() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        // The wrong password derives the wrong wrapping key, so the tag is what rejects it. Nothing
        // about the file is malformed, so this must NOT be reported as a structural problem — login
        // shows "wrong password, try again" for exactly this case.
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(file.bytes, NEW_PASSWORD) }
    }

    @Test
    fun rejectsAModifiedMagic() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[0] = (bytes[0] + 1).toByte()
        assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedVersion() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[KeyringEnvelope.VERSION_OFFSET] = 2
        assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedKdfId() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[KeyringEnvelope.KDF_ID_OFFSET] = 2
        assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedTimeCost() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        file.bytes[KeyringEnvelope.TIME_COST_OFFSET] = 1
        assertRangeRejection("time cost") { KeyringEnvelope.unwrap(file.bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedMemoryCost() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        file.bytes[KeyringEnvelope.MEMORY_KIB_OFFSET] = 1
        assertRangeRejection("memory cost") { KeyringEnvelope.unwrap(file.bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedParallelism() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        file.bytes[KeyringEnvelope.PARALLELISM_OFFSET] = 1
        assertRangeRejection("parallelism") { KeyringEnvelope.unwrap(file.bytes, PASSWORD) }
    }

    @Test
    fun rejectsAnInRangeCostEditThatSurvivesValidation() {
        // t=2 -> t=3 stays inside every bound, so this is the case that must be caught by the
        // derivation + AAD binding rather than by range validation.
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        file.bytes[KeyringEnvelope.TIME_COST_OFFSET + 3] = 3
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(file.bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedSaltLength() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[KeyringEnvelope.SALT_LEN_OFFSET] = 32
        val error = assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
        assertTrue(error.message!!.contains("salt length"), "message was: ${error.message}")
    }

    @Test
    fun rejectsAModifiedSalt() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[KeyringEnvelope.SALT_OFFSET] = (bytes[KeyringEnvelope.SALT_OFFSET] + 1).toByte()
        // A structurally valid file whose tag does not verify is indistinguishable from a typo, and
        // VaultFailure documents that it reports the recoverable one rather than inventing a
        // distinguisher. Pinned to the concrete subclass so that choice cannot drift silently.
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedNonce() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        bytes[KeyringEnvelope.NONCE_OFFSET] = (bytes[KeyringEnvelope.NONCE_OFFSET] + 1).toByte()
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAModifiedCiphertext() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        val i = KeyringEnvelope.WRAPPED_DMK_OFFSET
        bytes[i] = (bytes[i] + 1).toByte()
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsACostBelowTheHasherFloorBeforeDeriving() {
        // One KiB under the shared floor. The keyring must refuse it itself; if it merely handed the
        // parameters to JvmPasswordHasher the message would be the hasher's "below floor" text.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        writeInt(bytes, KeyringEnvelope.MEMORY_KIB_OFFSET, 19_455)
        val error = assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes, PASSWORD) }
        assertTrue(error.message!!.contains("out of range"), "message was: ${error.message}")
        assertFalse(error.message!!.contains("below floor"), "validation must precede the hasher")
    }

    @Test
    fun rejectsAnAbsurdCostBeforeDeriving() {
        // 1 TiB of Argon2 memory clears every floor. If this reached Argon2BytesGenerator the test
        // would die allocating, so a clean IllegalArgumentException proves validation ran first.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        writeInt(bytes, KeyringEnvelope.MEMORY_KIB_OFFSET, 1 shl 30)
        assertRangeRejection("memory cost") { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    // --- Ceiling coverage -------------------------------------------------------------------
    //
    // The single-MSB tamper cases above are not on their own evidence that the ceilings work. Flipping
    // the top byte of a cost field produces roughly 16.8 million, and BouncyCastle 1.85 has its own
    // limits there — m > 16777216 KiB is "memory out of range", p > 16777215 is "lanes must be at most
    // 16777215" — so with the ceilings deleted BC rejects two of those three itself, and the third
    // (t = 16777218) simply runs for hours.
    //
    // The three tests below instead use values BC accepts and completes: 8 GiB of memory, t=65 and
    // p=17 all reach Argon2BytesGenerator, so nothing but the keyring's own ceiling can reject them.
    // Verified by mutation: with the three ceilings removed these fail in under a second with
    // OutOfMemoryError, AEADBadTagException and AEADBadTagException respectively.

    @Test
    fun rejectsAMemoryCostAboveTheCeilingThatBouncyCastleWouldAccept() {
        // 8 GiB: comfortably inside BC's own 16 GiB limit, far outside the keyring's 256 MiB ceiling.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        writeInt(bytes, KeyringEnvelope.MEMORY_KIB_OFFSET, 8 shl 20)
        assertRangeRejection("memory cost") { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsATimeCostAboveTheCeilingThatBouncyCastleWouldAccept() {
        // t=65 is a legal Argon2 iteration count; it is simply more work than any honest keyring
        // asks for, and an attacker who can rewrite the header can use it to stall every login.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        writeInt(bytes, KeyringEnvelope.TIME_COST_OFFSET, 65)
        assertRangeRejection("time cost") { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun rejectsAParallelismAboveTheCeilingThatBouncyCastleWouldAccept() {
        // p=17 is legal for BC (its limit is 16777215) and satisfies Argon2's m >= 8p rule at 19 MiB.
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        writeInt(bytes, KeyringEnvelope.PARALLELISM_OFFSET, 17)
        assertRangeRejection("parallelism") { KeyringEnvelope.unwrap(bytes, PASSWORD) }
    }

    @Test
    fun ceilingsSitWhereTheThreatModelPutsThem() {
        // 256 MiB, not 1 GiB: Android hands a process roughly 128-512 MB, so any ceiling above that
        // still lets a tampered header OOM the app before authentication — precisely the failure the
        // ceiling exists to prevent. Pinned numerically because raising it is a security regression
        // that no round trip would notice.
        assertEquals(1 shl 18, KeyringEnvelope.MAX_ARGON2_MEMORY_KIB, "256 MiB")
        assertEquals(64, KeyringEnvelope.MAX_ARGON2_ITERATIONS)
        assertEquals(16, KeyringEnvelope.MAX_ARGON2_PARALLELISM)

        // The other side of the bracket: a ceiling below the production parameters would make every
        // keyring already on disk permanently unreadable.
        val production = KdfParams.ARGON2ID_DEFAULT
        assertTrue(production.memoryKib <= KeyringEnvelope.MAX_ARGON2_MEMORY_KIB, "default memory")
        assertTrue(production.iterations <= KeyringEnvelope.MAX_ARGON2_ITERATIONS, "default t")
        assertTrue(production.parallelism <= KeyringEnvelope.MAX_ARGON2_PARALLELISM, "default p")
    }

    @Test
    fun rejectsATruncatedFileWithoutAnIndexException() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        for (length in 0 until KeyringEnvelope.FILE_BYTES) {
            assertFailsWith<VaultFailure.Malformed>("truncation to $length bytes") {
                KeyringEnvelope.unwrap(bytes.copyOfRange(0, length), PASSWORD)
            }
        }
    }

    @Test
    fun rejectsTrailingBytes() {
        val bytes = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).bytes
        assertFailsWith<VaultFailure.Malformed> { KeyringEnvelope.unwrap(bytes + byteArrayOf(0), PASSWORD) }
    }

    @Test
    fun wrappedKeyIsBoundToTheWholeHeaderAsAad() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        val wrapKey = JvmPasswordHasher().derive(PASSWORD, salt(file.bytes), TEST_PARAMS)
        val header = file.bytes.copyOfRange(0, KeyringEnvelope.WRAPPED_DMK_OFFSET)
        val wrapped = file.bytes.copyOfRange(KeyringEnvelope.WRAPPED_DMK_OFFSET, file.bytes.size)

        assertContentEquals(file.dmk, gcmDecrypt(wrapKey, nonce(file.bytes), wrapped, header))
        assertFailsWith<GeneralSecurityException>("AAD must cover every header byte, not nothing") {
            gcmDecrypt(wrapKey, nonce(file.bytes), wrapped, aad = null)
        }
        assertFailsWith<GeneralSecurityException>("AAD must cover every header byte, not a prefix") {
            gcmDecrypt(wrapKey, nonce(file.bytes), wrapped, aad = header.copyOfRange(0, header.size - 1))
        }
    }

    @Test
    fun createRejectsANonArgon2idParameterSet() {
        assertFailsWith<IllegalArgumentException> {
            KeyringEnvelope.create(PASSWORD, KdfParams.LEGACY_PBKDF2)
        }
    }

    @Test
    fun rewrapPreservesTheDeviceMasterKey() {
        val file = KeyringEnvelope.create(PASSWORD, TEST_PARAMS)
        val dmk = KeyringEnvelope.unwrap(file.bytes, PASSWORD)
        val rewrapped = KeyringEnvelope.rewrap(dmk, NEW_PASSWORD, TEST_PARAMS)
        assertFalse(rewrapped.contentEquals(file.bytes), "rewrapping must produce a different file")
        assertContentEquals(dmk, KeyringEnvelope.unwrap(rewrapped, NEW_PASSWORD))
        assertFailsWith<VaultFailure.WrongPassword> { KeyringEnvelope.unwrap(rewrapped, PASSWORD) }
    }

    @Test
    fun rewrapDrawsAFreshSaltAndNonceEveryTime() {
        // Same DMK, same password, same params: if either the salt or the nonce were reused, two
        // rewraps would share a (key, nonce) pair, which is a key-recovery bug in GCM.
        val dmk = KeyringEnvelope.create(PASSWORD, TEST_PARAMS).dmk
        val first = KeyringEnvelope.rewrap(dmk, PASSWORD, TEST_PARAMS)
        val second = KeyringEnvelope.rewrap(dmk, PASSWORD, TEST_PARAMS)
        assertFalse(salt(first).contentEquals(salt(second)), "salt must be fresh per rewrap")
        assertFalse(nonce(first).contentEquals(nonce(second)), "nonce must be fresh per rewrap")
        assertContentEquals(dmk, KeyringEnvelope.unwrap(first, PASSWORD))
        assertContentEquals(dmk, KeyringEnvelope.unwrap(second, PASSWORD))
    }

    @Test
    fun rewrapRejectsAWrongLengthKey() {
        assertFailsWith<IllegalArgumentException> {
            KeyringEnvelope.rewrap(ByteArray(31), PASSWORD, TEST_PARAMS)
        }
    }

    /**
     * The cost ceilings must reject the header themselves, before the parameters ever reach
     * Argon2BytesGenerator. The type alone no longer proves that — the keyring throws
     * [VaultFailure.Malformed] where BouncyCastle throws [IllegalArgumentException] — but it also does
     * not prove the *right* ceiling fired: one predicate backs all three fields, so a bound copied
     * into the wrong branch would still produce a Malformed. Asserting the message names the offending
     * field is what pins each rejection to its own parameter.
     */
    private fun assertRangeRejection(field: String, block: () -> Unit) {
        val error = assertFailsWith<VaultFailure.Malformed>(block = block)
        val message = error.message.orEmpty()
        assertTrue(message.contains("keyring argon2id $field out of range"), "message was: $message")
    }

    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    private fun salt(bytes: ByteArray) =
        bytes.copyOfRange(KeyringEnvelope.SALT_OFFSET, KeyringEnvelope.SALT_OFFSET + 48)

    private fun nonce(bytes: ByteArray) =
        bytes.copyOfRange(KeyringEnvelope.NONCE_OFFSET, KeyringEnvelope.NONCE_OFFSET + 12)

    private fun gcmDecrypt(key: ByteArray, nonce: ByteArray, ct: ByteArray, aad: ByteArray?): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            aad?.let { updateAAD(it) }
        }.doFinal(ct)

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

    private companion object {
        const val PASSWORD = "correct horse battery staple"
        const val NEW_PASSWORD = "a completely different horse"

        /**
         * A keyring produced once from fixed inputs — salt `00..2f`, nonce `a0..ab`, DMK below,
         * Argon2id t=2 / m=19456 / p=1 — and frozen here. Regenerating it rather than fixing the code
         * would defeat the point: this is the only assertion in the suite that fails when the format
         * changes but both the writer and the reader change with it.
         */
        const val GOLDEN_PASSWORD = "golden vector password"
        const val GOLDEN_FILE =
            "504d4b5201010000000200004c000000000130000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
                "a0a1a2a3a4a5a6a7a8a9aaab" +
                "4d3954c36f85934546b614aef5b950d6a3e632e0c56eed994a4e3ad6256dbc2d" +
                "617705bd6029ceae6aaad036aca1a0b6"
        const val GOLDEN_DMK = "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc"

        /** OWASP minimum configuration — the cheapest set the shared cost floors accept. */
        val TEST_PARAMS = KdfParams(
            algorithm = KdfParams.ARGON2ID,
            keyLengthBytes = 32,
            iterations = 2,
            memoryKib = 19_456,
            parallelism = 1,
        )
    }
}
