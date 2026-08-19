package ai.passman.crypto.keyring

import ai.passman.crypto.vault.VaultFailure
import ai.passman.crypto.vault.VaultSessionKey
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
 * Two rules this file keeps, both inherited from [KeyringEnvelopeTest]:
 *
 * 1. **No `assertFails`.** It wraps `runCatching`, which catches `Throwable`, so an `OutOfMemoryError`
 *    would read as a pass. Every rejection asserts the specific type it should get —
 *    [VaultFailure.Malformed] for bytes the envelope refuses to act on at all, [VaultFailure.Tampered]
 *    for a tag that should not verify. Collapsing the two would erase the distinction the quarantine
 *    decision in the key managers is built on.
 * 2. **Layout assertions use literal numbers.** Reading the header back through the same constants
 *    that wrote it makes swapping two offsets invisible while the on-disk format silently changes.
 */
class KeyFileEnvelopeTest {

    private val dmk = ByteArray(32) { it.toByte() }
    private val sessionKey get() = VaultSessionKey(dmk.copyOf())

    private val hybridBlob = ByteArray(1_216) { (it * 7).toByte() }
    private val mlDsaBlob = ByteArray(32) { (0xA0 + it).toByte() }

    // --- round trip ---------------------------------------------------------------------------

    @Test
    fun roundTripsAHybridKeyBlob() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertContentEquals(hybridBlob, KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, sessionKey))
    }

    @Test
    fun roundTripsAnMlDsaSeed() {
        val sealed = KeyFileEnvelope.seal(mlDsaBlob, KeyFilePurpose.ML_DSA, sessionKey)
        assertContentEquals(mlDsaBlob, KeyFileEnvelope.open(sealed, KeyFilePurpose.ML_DSA, sessionKey))
    }

    /** The smallest legal file. A minimum-length check that is off by one shows up here and nowhere else. */
    @Test
    fun roundTripsAnEmptyPlaintext() {
        val sealed = KeyFileEnvelope.seal(ByteArray(0), KeyFilePurpose.HYBRID, sessionKey)
        assertEquals(KeyFileEnvelope.MIN_FILE_BYTES, sealed.size)
        assertContentEquals(ByteArray(0), KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, sessionKey))
    }

    @Test
    fun everySealDrawsAFreshNonce() {
        val a = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        val b = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertFalse(a.contentEquals(b), "identical plaintext under a fixed key must not produce identical bytes")
        assertFalse(
            a.copyOfRange(6, 18).contentEquals(b.copyOfRange(6, 18)),
            "nonce reuse under one key is a GCM key-recovery break, not a cosmetic issue",
        )
    }

    // --- layout -------------------------------------------------------------------------------

    /**
     * Literal offsets, deliberately. The header is 18 bytes: `"PMKF" | version | purpose | nonce(12)`.
     */
    @Test
    fun headerLayoutIsMagicVersionPurposeNonce() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertContentEquals("PMKF".encodeToByteArray(), sealed.copyOfRange(0, 4))
        assertEquals(1.toByte(), sealed[4], "version(1) at 4")
        assertEquals(1.toByte(), sealed[5], "purpose(1) at 5, HYBRID = 1")
        assertEquals(18, KeyFileEnvelope.HEADER_BYTES, "nonce(12) at 6 ends the header at 18")
        assertEquals(hybridBlob.size + 18 + 16, sealed.size, "header + ciphertext + 16-byte tag")

        val mlDsa = KeyFileEnvelope.seal(mlDsaBlob, KeyFilePurpose.ML_DSA, sessionKey)
        assertEquals(2.toByte(), mlDsa[5], "purpose(1) at 5, ML_DSA = 2")
    }

    /**
     * The magic is what tells a keyring-wrapped key file apart from the RSA-wrapped one it replaces,
     * so it must not collide with `CryptoEnvelope`'s "PMNV" — which it would if only the last byte
     * were checked.
     */
    @Test
    fun magicIsDistinctFromTheRsaEnvelopeMagic() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertTrue(KeyFileEnvelope.isKeyFileEnvelope(sealed))
        assertFalse(KeyFileEnvelope.isKeyFileEnvelope("PMNV".encodeToByteArray() + ByteArray(64)))
        assertFalse(KeyFileEnvelope.isKeyFileEnvelope("garbage".encodeToByteArray()))
        assertFalse(KeyFileEnvelope.isKeyFileEnvelope(ByteArray(0)))
        assertFalse(KeyFileEnvelope.isKeyFileEnvelope("PMKF".encodeToByteArray()), "too short to carry a purpose")
    }

    /**
     * The plan's whole reason for this envelope: the file key is the DMK's HKDF subkey and nothing
     * that touches the vault. Decrypting by hand with [KeyringSubkeys.hybridKeyFileKey] is the only
     * assertion here that would fail if the implementation quietly switched labels — asking
     * [KeyFileEnvelope.open] instead would just be testing it against itself.
     */
    @Test
    fun theFileKeyIsTheHybridKeyringSubkey() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertContentEquals(hybridBlob, decryptWith(KeyringSubkeys.hybridKeyFileKey(dmk), sealed))
    }

    @Test
    fun theMlDsaFileKeyIsTheMlDsaKeyringSubkey() {
        val sealed = KeyFileEnvelope.seal(mlDsaBlob, KeyFilePurpose.ML_DSA, sessionKey)
        assertContentEquals(mlDsaBlob, decryptWith(KeyringSubkeys.mlDsaKeyFileKey(dmk), sealed))
    }

    // --- rejections ---------------------------------------------------------------------------

    /** A `hybrid.key` copied over `mldsa.key` is refused by name, before any key is derived. */
    @Test
    fun rejectsAFileSealedForTheOtherPurpose() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        assertFailsWith<VaultFailure.Malformed> {
            KeyFileEnvelope.open(sealed, KeyFilePurpose.ML_DSA, sessionKey)
        }
    }

    /**
     * ...and rewriting the purpose byte to get past that check does not help, because the header is
     * bound as associated data *and* the two purposes derive different keys. Without the AAD binding
     * this would be the one header field an attacker could edit freely.
     */
    @Test
    fun rejectsARewrittenPurposeByte() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        sealed[5] = 2
        assertFailsWith<VaultFailure.Tampered> {
            KeyFileEnvelope.open(sealed, KeyFilePurpose.ML_DSA, sessionKey)
        }
    }

    @Test
    fun rejectsANonEnvelope() {
        assertFailsWith<VaultFailure.Malformed> {
            KeyFileEnvelope.open("garbage".encodeToByteArray(), KeyFilePurpose.HYBRID, sessionKey)
        }
    }

    @Test
    fun rejectsAnUnsupportedVersion() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        sealed[4] = 2
        assertFailsWith<VaultFailure.Malformed> {
            KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, sessionKey)
        }
    }

    /** Truncation must be a typed failure, not an `IndexOutOfBoundsException` out of a slice. */
    @Test
    fun rejectsATruncatedFileWithoutAnIndexException() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        listOf(6, 17, 18, KeyFileEnvelope.MIN_FILE_BYTES - 1).forEach { size ->
            assertFailsWith<VaultFailure.Malformed>("truncated to $size bytes") {
                KeyFileEnvelope.open(sealed.copyOf(size), KeyFilePurpose.HYBRID, sessionKey)
            }
        }
    }

    @Test
    fun rejectsAModifiedMagic() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        sealed[3] = 0x56 // "PMKV"
        assertFailsWith<VaultFailure.Malformed> {
            KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, sessionKey)
        }
    }

    @Test
    fun rejectsAModifiedNonceOrCiphertext() {
        listOf(6, 17, 18, 40).forEach { index ->
            val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
            sealed[index] = (sealed[index] + 1).toByte()
            assertFailsWith<VaultFailure.Tampered>("byte $index must be covered by the tag") {
                KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, sessionKey)
            }
        }
    }

    @Test
    fun rejectsADifferentDeviceMasterKey() {
        val sealed = KeyFileEnvelope.seal(hybridBlob, KeyFilePurpose.HYBRID, sessionKey)
        val other = VaultSessionKey(dmk.copyOf().also { it[31] = (it[31] + 1).toByte() })
        assertFailsWith<VaultFailure.Tampered> {
            KeyFileEnvelope.open(sealed, KeyFilePurpose.HYBRID, other)
        }
    }

    /** Hand-rolled so the assertion does not depend on the code under test agreeing with itself. */
    private fun decryptWith(key: ByteArray, sealed: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, sealed.copyOfRange(6, 18)),
            )
            updateAAD(sealed.copyOfRange(0, 18))
        }.doFinal(sealed.copyOfRange(18, sealed.size))
}
