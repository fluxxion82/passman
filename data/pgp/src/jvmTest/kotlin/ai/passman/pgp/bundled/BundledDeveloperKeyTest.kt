package ai.passman.pgp.bundled

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Holds [BundledDeveloperKey] honest: the armor constant survived transcription (a mangled
 * base64 body fails the CRC and never parses), its primary key is exactly the pinned
 * fingerprint the import path verifies against, and the blob carries no secret-key material —
 * the one thing that must never ship inside the app binary.
 */
class BundledDeveloperKeyTest {

    private fun parseAll(): List<Any> {
        BundledDeveloperKey.ARMOR.byteInputStream().use { stream ->
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(stream), JcaKeyFingerprintCalculator())
            return generateSequence { factory.nextObject() }.toList()
        }
    }

    @Test
    fun armorParsesToExactlyOnePublicKeyRing() {
        val objects = parseAll()

        assertEquals(1, objects.size, "expected a single object in the bundled armor, got: $objects")
        assertTrue(objects.single() is PGPPublicKeyRing)
    }

    @Test
    fun primaryFingerprintMatchesThePinnedConstant() {
        val ring = parseAll().filterIsInstance<PGPPublicKeyRing>().single()
        val primary = ring.publicKeys.asSequence().single { it.isMasterKey }

        val fingerprint = primary.fingerprint.joinToString("") { byte -> String.format("%02X", byte) }

        assertEquals(BundledDeveloperKey.FINGERPRINT, fingerprint)
    }

    @Test
    fun armorContainsNoSecretKeyPackets() {
        val objects = parseAll()

        assertTrue(
            objects.none { it is PGPSecretKeyRing },
            "the bundled developer key must never carry secret-key material",
        )
    }
}
