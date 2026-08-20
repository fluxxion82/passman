package ai.passman.pgp.utils

import ai.passman.keys.model.RSA
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

/**
 * A ring that arrived from a newer peer is safe to *hold* — sync copies key files byte for byte, so
 * it round-trips losslessly and a later app version can use it. It is not safe to *encrypt to*:
 * BouncyCastle drops a v4 subkey whose algorithm it does not know, and every subkey after it, while
 * reporting the ring as whole. Encrypting to whatever survived means picking a key the peer may have
 * moved off, and the peer failing to decrypt for a reason neither side can see.
 */
class EncryptionKeyGuardTest {

    private lateinit var dir: File

    @BeforeTest
    fun setUp() {
        dir = Files.createTempDirectory("encryption-key-guard-test").toFile()
    }

    @AfterTest
    fun tearDown() {
        dir.deleteRecursively()
    }

    @Test
    fun `a readable ring still yields an encryption key`() {
        val file = File(dir, "good_public_ring.asc").apply {
            FileOutputStream(this).use { out ->
                ArmoredOutputStream(out).use { it.write(ring().encoded) }
            }
        }

        assertNotNull(PgpKeys.readPublicKey(file.absolutePath))
    }

    @Test
    fun `a ring carrying an unreadable algorithm is refused rather than partially used`() {
        val doctored = File(dir, "future_public_ring.asc").apply {
            writeBytes(binaryRing() + unknownAlgorithmSubkeyPacket())
        }

        // Establish the premise: BouncyCastle still hands back a ring, minus the subkey it dropped.
        // Without the guard, readPublicKey would happily pick a key out of that truncated view.
        val parsed = JcaPGPObjectFactory(ByteArrayInputStream(doctored.readBytes())).nextObject()
        assertTrue(parsed is PGPPublicKeyRing, "premise: BC must still parse a ring, got $parsed")

        val failure = assertFailsWith<IllegalArgumentException> {
            PgpKeys.readPublicKey(doctored.absolutePath)
        }
        assertTrue(
            failure.message.orEmpty().contains("35"),
            "the refusal should name the algorithm so the user can act on it: ${failure.message}",
        )
    }

    private fun ring(): PGPPublicKeyRing =
        PgpKeys.createPgpKeyRingGenerator(
            "Test <test@example.com>",
            RSA,
            2048,
            0,
            "password",
        ).generatePublicKeyRing()

    /** The ring as binary packets, so a crafted packet can be appended where the dearmorer sees it. */
    private fun binaryRing(): ByteArray =
        PGPUtil.getDecoderStream(ByteArrayInputStream(ring().encoded)).use { it.readBytes() }

    /** One public-subkey packet using algorithm 35 (ML-KEM in the RFC 9580 registry). */
    private fun unknownAlgorithmSubkeyPacket(): ByteArray {
        val body = mutableListOf<Byte>()
        body += 4 // version
        repeat(4) { body += 0x00 } // creation time
        body += 35
        repeat(32) { body += 0x2A } // stand-in key material
        val header = (0x80 or (14 shl 2)).toByte() // old format, public subkey, one-byte length
        return byteArrayOf(header, body.size.toByte()) + body.toByteArray()
    }
}
