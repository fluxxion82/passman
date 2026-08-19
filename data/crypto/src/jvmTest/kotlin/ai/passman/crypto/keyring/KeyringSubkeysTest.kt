package ai.passman.crypto.keyring

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

class KeyringSubkeysTest {

    private val dmk = ByteArray(32) { it.toByte() }

    /**
     * All **four** labels the plan defines. The PKCS#12 password is decoded back to its 32 raw bytes
     * so it takes part in the collision and avalanche checks like every other subkey — omitting it
     * would leave the one label whose output is handed to a non-memory-hard KDF as the only label
     * never checked against the others.
     */
    private fun allSubkeys(key: ByteArray) = listOf(
        KeyringSubkeys.vaultWrapKey(key),
        KeyringSubkeys.hybridKeyFileKey(key),
        KeyringSubkeys.mlDsaKeyFileKey(key),
        Base64.getDecoder().decode(KeyringSubkeys.pkcs12Password(key)),
    )

    @Test
    fun everyLabelProducesADistinct32ByteKey() {
        val keys = allSubkeys(dmk)
        assertEquals(4, keys.size, "the plan defines four labels")
        keys.forEach { assertEquals(32, it.size) }
        assertEquals(keys.size, keys.map { it.toList() }.toSet().size, "labels must not collide")
    }

    @Test
    fun derivationIsDeterministic() {
        allSubkeys(dmk).zip(allSubkeys(dmk.copyOf())).forEach { (a, b) -> assertContentEquals(a, b) }
        assertEquals(KeyringSubkeys.pkcs12Password(dmk), KeyringSubkeys.pkcs12Password(dmk.copyOf()))
    }

    @Test
    fun oneByteChangeInTheKeyChangesEverySubkey() {
        val other = dmk.copyOf().also { it[7] = (it[7] + 1).toByte() }
        allSubkeys(dmk).zip(allSubkeys(other)).forEach { (a, b) ->
            assertFalse(a.contentEquals(b), "subkey must depend on the whole device master key")
        }
        assertFalse(KeyringSubkeys.pkcs12Password(dmk) == KeyringSubkeys.pkcs12Password(other))
    }

    @Test
    fun pkcs12PasswordIsUnpaddedBase64() {
        val password = KeyringSubkeys.pkcs12Password(dmk)
        assertTrue(password.length >= 43, "32 bytes of base64 is 43 characters, was ${password.length}")
        assertFalse(password.contains('='), "padding must be stripped")
        assertTrue(password.all { it in BASE64_ALPHABET }, "outside the base64 alphabet: $password")
    }

    @Test
    fun labelsAndSaltMatchTheSpecifiedDerivation() {
        // Format lock: these four strings are the wire contract. Changing either the HKDF salt or a
        // label silently invalidates every existing keyring-derived artifact on disk.
        assertContentEquals(hkdf("passman/vault-wrap/v1"), KeyringSubkeys.vaultWrapKey(dmk))
        assertContentEquals(hkdf("passman/keyfile/hybrid/v1"), KeyringSubkeys.hybridKeyFileKey(dmk))
        assertContentEquals(hkdf("passman/keyfile/mldsa/v1"), KeyringSubkeys.mlDsaKeyFileKey(dmk))
        assertEquals(
            Base64.getEncoder().withoutPadding().encodeToString(hkdf("passman/pkcs12-password/v1")),
            KeyringSubkeys.pkcs12Password(dmk),
        )
    }

    @Test
    fun rejectsAWrongLengthDeviceMasterKey() {
        assertFailsWith<IllegalArgumentException> { KeyringSubkeys.vaultWrapKey(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { KeyringSubkeys.hybridKeyFileKey(ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> { KeyringSubkeys.mlDsaKeyFileKey(ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { KeyringSubkeys.pkcs12Password(ByteArray(16)) }
    }

    private fun hkdf(label: String): ByteArray {
        val generator = HKDFBytesGenerator(SHA256Digest()).apply {
            init(HKDFParameters(dmk, "passman-keyring-v1".encodeToByteArray(), label.encodeToByteArray()))
        }
        return ByteArray(32).also { generator.generateBytes(it, 0, it.size) }
    }

    private companion object {
        val BASE64_ALPHABET = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('+', '/')
    }
}
