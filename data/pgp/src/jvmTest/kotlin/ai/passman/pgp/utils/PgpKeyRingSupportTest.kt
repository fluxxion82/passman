package ai.passman.pgp.utils

import ai.passman.pgp.bundled.BundledDeveloperKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The algorithm ids here are deliberately ones no OpenPGP implementation assigns today: 35 is
 * ML-KEM in the RFC 9580 registry, 30 is ML-DSA. They stand in for "a key from a newer build than
 * this one", which is the whole point of the guard.
 */
class PgpKeyRingSupportTest {

    @Test
    fun `the bundled developer key is supported`() {
        assertEquals(
            PgpKeyRingSupport.Supported,
            inspectKeyRingSupport(BundledDeveloperKey.ARMOR.toByteArray()),
        )
    }

    @Test
    fun `a v4 primary with an unknown algorithm is reported by id`() {
        val packets = keyPacket(tag = TAG_PUBLIC_KEY, version = 4, algorithm = ML_KEM)

        assertEquals(PgpKeyRingSupport.UnsupportedAlgorithm(ML_KEM), inspectKeyRingSupport(packets))
    }

    @Test
    fun `a v6 key with an unknown algorithm is reported rather than accepted`() {
        // The case BouncyCastle accepts outright, as an opaque blob with a nonsense bit strength.
        val packets = keyPacket(tag = TAG_PUBLIC_KEY, version = 6, algorithm = ML_KEM)

        assertEquals(PgpKeyRingSupport.UnsupportedAlgorithm(ML_KEM), inspectKeyRingSupport(packets))
    }

    @Test
    fun `an unknown subkey is caught even though the ring parses without it`() {
        val ring = developerRingBytes()
        val withSubkey = ring + keyPacket(tag = TAG_PUBLIC_SUBKEY, version = 4, algorithm = ML_KEM)

        // Establish the premise first: BC reports this ring as fine, having dropped the subkey.
        val parsed = JcaPGPObjectFactory(ByteArrayInputStream(withSubkey)).nextObject()
        assertTrue(parsed is PGPPublicKeyRing, "expected BC to still parse a ring, got $parsed")
        assertTrue(
            parsed.publicKeys.asSequence().none { it.algorithm == ML_KEM },
            "premise broken: BC now surfaces the unknown subkey, so this guard can be simplified",
        )

        assertEquals(PgpKeyRingSupport.UnsupportedAlgorithm(ML_KEM), inspectKeyRingSupport(withSubkey))
    }

    @Test
    fun `a supported subkey after an unsupported one does not mask it`() {
        val packets = developerRingBytes() +
            keyPacket(tag = TAG_PUBLIC_SUBKEY, version = 4, algorithm = ML_DSA) +
            keyPacket(tag = TAG_PUBLIC_SUBKEY, version = 4, algorithm = RSA)

        assertEquals(PgpKeyRingSupport.UnsupportedAlgorithm(ML_DSA), inspectKeyRingSupport(packets))
    }

    @Test
    fun `the private experimental range is not treated as supported`() {
        val packets = keyPacket(tag = TAG_PUBLIC_KEY, version = 4, algorithm = 100)

        assertEquals(PgpKeyRingSupport.UnsupportedAlgorithm(100), inspectKeyRingSupport(packets))
    }

    @Test
    fun `garbage is not a key ring`() {
        assertEquals(PgpKeyRingSupport.NotAKeyRing, inspectKeyRingSupport(ByteArray(64) { it.toByte() }))
    }

    @Test
    fun `an empty input is not a key ring`() {
        assertEquals(PgpKeyRingSupport.NotAKeyRing, inspectKeyRingSupport(ByteArray(0)))
    }

    @Test
    fun `armor carrying no key packets is not a key ring`() {
        // A literal-data packet: structurally valid OpenPGP, just not keys.
        val literalData = byteArrayOf(0xCB.toByte(), 0x06, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00)

        assertEquals(PgpKeyRingSupport.NotAKeyRing, inspectKeyRingSupport(literalData))
    }

    @Test
    fun `a truncated key packet is not a key ring`() {
        val full = keyPacket(tag = TAG_PUBLIC_KEY, version = 4, algorithm = RSA)

        assertEquals(PgpKeyRingSupport.NotAKeyRing, inspectKeyRingSupport(full.copyOf(full.size / 2)))
    }

    // ---- fixtures -------------------------------------------------------------------------

    /** The bundled key as binary packets, so crafted packets can be appended to a real ring. */
    private fun developerRingBytes(): ByteArray =
        PGPUtil.getDecoderStream(ByteArrayInputStream(BundledDeveloperKey.ARMOR.toByteArray()))
            .use { it.readBytes() }
            .also {
                // Sanity: it must really be a ring, or the appended-subkey tests prove nothing.
                val ring = JcaPGPObjectFactory(ByteArrayInputStream(it)).nextObject()
                require(ring is PGPPublicKeyRing) { "fixture is not a public ring: $ring" }
            }

    /**
     * One old-format key packet with the given version and algorithm, padded with enough dummy
     * key material to look plausible. Only the header and the first few body bytes are ever read.
     */
    private fun keyPacket(tag: Int, version: Int, algorithm: Int): ByteArray {
        val body = mutableListOf<Byte>()
        body += version.toByte()
        repeat(4) { body += 0x00 } // creation time
        if (version <= 3) repeat(2) { body += 0x00 } // validity period
        body += algorithm.toByte()
        if (version >= 5) repeat(4) { body += 0x00 } // key material length
        repeat(32) { body += 0x2A } // stand-in key material

        val header = (0x80 or (tag shl 2)).toByte() // old format, one-byte length
        return byteArrayOf(header, body.size.toByte()) + body.toByteArray()
    }

    private companion object {
        const val RSA = 1
        const val ML_DSA = 30
        const val ML_KEM = 35
        const val TAG_PUBLIC_KEY = 6
        const val TAG_PUBLIC_SUBKEY = 14
    }
}
