package ai.passman.crypto.kdf

import ai.passman.domain.user.models.KdfParams
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JvmPasswordHasherTest {
    private val hasher = JvmPasswordHasher()
    private val salt = ByteArray(48) { it.toByte() }

    @Test
    fun legacyPbkdf2_reproducesTheOldAlgorithmExactly() {
        // Back-compat guarantee: a credential stored by the pre-versioning code (PBKDF2-HMAC-SHA256,
        // 130k iterations, 2048-bit output) must still verify — i.e. LEGACY_PBKDF2 derives the same
        // bytes the old code did. Compute the reference directly and compare.
        val reference = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec("hunter2".toCharArray(), salt, 130_000, 2048))
            .encoded
        val derived = hasher.derive("hunter2", salt, KdfParams.LEGACY_PBKDF2)
        assertContentEquals(reference, derived)
        assertEquals(256, derived.size, "2048-bit output = 256 bytes")
    }

    @Test
    fun argon2id_isDeterministicForSameInputs() {
        val a = hasher.derive("pw", salt, KdfParams.ARGON2ID_DEFAULT)
        val b = hasher.derive("pw", salt, KdfParams.ARGON2ID_DEFAULT)
        assertContentEquals(a, b)
        assertEquals(32, a.size, "argon2id default output = 32 bytes")
    }

    @Test
    fun argon2id_differsFromPbkdf2AndOnWrongPassword() {
        val argon = hasher.derive("pw", salt, KdfParams.ARGON2ID_DEFAULT)
        val pbkdf2 = hasher.derive("pw", salt, KdfParams.LEGACY_PBKDF2)
        assertFalse(argon.contentEquals(pbkdf2.copyOf(32)), "different KDFs must not collide")

        val wrong = hasher.derive("PW", salt, KdfParams.ARGON2ID_DEFAULT)
        assertFalse(argon.contentEquals(wrong), "different password -> different hash")
    }

    @Test
    fun differentSalts_giveDifferentHashes() {
        val other = ByteArray(48) { (it + 1).toByte() }
        assertFalse(
            hasher.derive("pw", salt, KdfParams.ARGON2ID_DEFAULT)
                .contentEquals(hasher.derive("pw", other, KdfParams.ARGON2ID_DEFAULT)),
        )
    }

    @Test
    fun unsupportedAlgorithm_throws() {
        val bad = KdfParams(algorithm = "scrypt", keyLengthBytes = 32)
        var threw = false
        try {
            hasher.derive("pw", salt, bad)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }
}
