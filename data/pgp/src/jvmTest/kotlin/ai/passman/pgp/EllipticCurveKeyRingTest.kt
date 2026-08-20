package ai.passman.pgp

import ai.passman.keys.model.ECDSA
import ai.passman.keys.model.ED25519
import ai.passman.keys.model.ED448
import ai.passman.keys.model.PGPKeyAlgo
import ai.passman.keys.model.X25519
import ai.passman.keys.model.X448
import ai.passman.pgp.utils.PgpHelper
import ai.passman.pgp.utils.PgpKeyRingSupport
import ai.passman.pgp.utils.PgpKeys
import ai.passman.pgp.utils.inspectKeyRingSupport
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags

/**
 * The elliptic-curve ring shapes, each proved end to end rather than by asserting the algorithm tag
 * alone — a ring whose packets carry the right numbers but cannot encrypt or sign is worse than no
 * ring, because it fails at use rather than at creation.
 *
 * All of these are v4 keys. RFC 9580 introduced the 25519/448 codepoints alongside v6, but the
 * pinned BouncyCastle builds them on v4 quite happily, and staying on v4 keeps this app's one
 * secret-key encryptor (SHA-1 checksum, iterated S2K) valid for every algorithm it generates.
 * Moving to v6 would mean a second protection path for these keys and nothing else.
 */
class EllipticCurveKeyRingTest {

    @Test
    fun `NIST ECDSA rings pair an ECDSA primary with an ECDH subkey`() {
        val (primary, subkey) = ringFor(ECDSA, length = 256)

        assertEquals(4, primary.version)
        assertEquals(PublicKeyAlgorithmTags.ECDSA, primary.algorithm)
        assertEquals(PublicKeyAlgorithmTags.ECDH, subkey.algorithm)
    }

    @Test
    fun `the requested length picks the NIST curve`() {
        // Same algorithm, three sizes: the dropdown's "length" is the only curve control there is,
        // so a length that did not reach the generator would silently give everyone P-256.
        assertEquals(256, ringFor(ECDSA, length = 256).first.bitStrength)
        assertEquals(384, ringFor(ECDSA, length = 384).first.bitStrength)
        assertEquals(521, ringFor(ECDSA, length = 521).first.bitStrength)
    }

    @Test
    fun `Ed25519 rings use the RFC 9580 codepoints, not the legacy pair`() {
        val (primary, subkey) = ringFor(ED25519, length = 256)

        assertEquals(4, primary.version)
        // 27 and 25, not the 22 and 18 the ED25519/EDDSA option has always produced.
        assertEquals(PublicKeyAlgorithmTags.Ed25519, primary.algorithm)
        assertEquals(PublicKeyAlgorithmTags.X25519, subkey.algorithm)
    }

    @Test
    fun `Ed448 rings pair Ed448 with X448`() {
        val (primary, subkey) = ringFor(ED448, length = 448)

        assertEquals(PublicKeyAlgorithmTags.Ed448, primary.algorithm)
        assertEquals(PublicKeyAlgorithmTags.X448, subkey.algorithm)
    }

    @Test
    fun `a curve primary certifies and signs, and its subkey only encrypts`() {
        for (algorithm in listOf(ECDSA, ED25519, ED448)) {
            val (primary, subkey) = ringFor(algorithm, length = lengthFor(algorithm))

            assertEquals(
                KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA,
                primary.signatures.asSequence().first().hashedSubPackets.keyFlags,
                "$algorithm primary must sign for itself - these families have no signing subkey",
            )
            assertEquals(
                KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE,
                subkey.signatures.asSequence().first().hashedSubPackets.keyFlags,
                "$algorithm subkey flags",
            )
        }
    }

    @Test
    fun `every curve ring encrypts, decrypts, signs and verifies`() {
        for (algorithm in listOf(ECDSA, ED25519, ED448)) {
            val generator = PgpKeys.createPgpKeyRingGenerator(
                "Test <test@example.com>",
                algorithm,
                lengthFor(algorithm),
                0,
                PASSWORD,
            )
            val secretRing = generator.generateSecretKeyRing()
            val publicRing = generator.generatePublicKeyRing()
            val encryptionSubkey = secretRing.publicKeys.asSequence().single { !it.isMasterKey }

            val plaintext = "$algorithm round trip".encodeToByteArray()
            val plainFile = Files.createTempFile("pgp-curve", ".txt").toFile().apply { writeBytes(plaintext) }
            val publicKeyFile = Files.createTempFile("pgp-curve", ".asc").toFile().apply {
                writeArmored(this, publicRing.encoded)
            }
            try {
                val encrypted = ByteArrayOutputStream()
                PgpHelper.encryptFile(encrypted, plainFile, encryptionSubkey, armor = false, withIntegrityCheck = true)

                val decrypted = ByteArrayOutputStream()
                PgpHelper.decryptFile(ByteArrayInputStream(encrypted.toByteArray()), decrypted, secretRing, PASSWORD)
                assertEquals(String(plaintext), decrypted.toString(), "$algorithm decrypt")

                val signed = PgpHelper.sign(
                    plaintext,
                    secretRing.secretKey,
                    PASSWORD,
                    armor = false,
                    digestName = "SHA512",
                )
                assertTrue(PgpHelper.verifySignature(signed, publicKeyFile.absolutePath), "$algorithm verify")
            } finally {
                plainFile.delete()
                publicKeyFile.delete()
            }
        }
    }

    @Test
    fun `the import guard accepts the rings this build now generates`() {
        // The guard's supported-algorithm set and the generator's repertoire have to agree, or the
        // app refuses to import a key it made itself.
        for (algorithm in listOf(ECDSA, ED25519, ED448)) {
            val ring = PgpKeys.createPgpKeyRingGenerator(
                "Test <test@example.com>",
                algorithm,
                lengthFor(algorithm),
                0,
                PASSWORD,
            ).generatePublicKeyRing()

            assertEquals(
                PgpKeyRingSupport.Supported,
                inspectKeyRingSupport(ring.encoded),
                "$algorithm ring must pass the import guard",
            )
        }
    }

    @Test
    fun `a key-agreement algorithm is refused as a ring's primary key`() {
        // X25519 and X448 can only encrypt. Asking for a ring of one used to be a TODO() and would
        // have thrown NotImplementedError from inside a coroutine; now it is a stated precondition.
        for (algorithm in listOf(X25519, X448)) {
            assertFailsWith<IllegalArgumentException>("$algorithm must be refused as a primary") {
                PgpKeys.createPgpKeyRingGenerator("Test <test@example.com>", algorithm, 256, 0, PASSWORD)
            }
        }
    }

    private fun lengthFor(algorithm: PGPKeyAlgo) = if (algorithm == ED448) 448 else 256

    private fun writeArmored(file: File, encoded: ByteArray) {
        ArmoredOutputStream(FileOutputStream(file)).use { it.write(encoded) }
    }

    /** The (primary, encryption subkey) pair of a freshly generated ring. */
    private fun ringFor(algorithm: PGPKeyAlgo, length: Int) =
        PgpKeys.createPgpKeyRingGenerator("Test <test@example.com>", algorithm, length, 0, PASSWORD)
            .generateSecretKeyRing()
            .publicKeys
            .asSequence()
            .toList()
            .let { keys -> keys.single { it.isMasterKey } to keys.single { !it.isMasterKey } }

    private companion object {
        const val PASSWORD = "password"
    }
}
