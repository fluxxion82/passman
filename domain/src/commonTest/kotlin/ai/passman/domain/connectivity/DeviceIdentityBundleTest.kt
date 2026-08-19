package ai.passman.domain.connectivity

import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.InvalidDeviceIdentityKeyLength
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeviceIdentityBundleTest {
    @Test
    fun `canonical encoding golden vector uses fixed big endian field offsets`() {
        val bundle = bundle(
            rsaSpki = byteArrayOf(0x10, 0x20, 0x30),
            hybridPublicKey = hybridPublicKey(0x41),
            mldsaPublicKey = ByteArray(1_952) { 0x52 },
            capabilityBits = 0x80000005u,
        )

        val encoded = bundle.canonicalEncoding()
        val expected =
            "passman-device-identity-v1".encodeToByteArray() +
                byteArrayOf(0x00, 0x03, 0x10, 0x20, 0x30, 0x04, 0xC2.toByte()) +
                hybridPublicKey(0x41) +
                byteArrayOf(0x07, 0xA0.toByte()) +
                ByteArray(1_952) { 0x52 } +
                byteArrayOf(0x80.toByte(), 0x00, 0x00, 0x05)

        assertContentEquals(expected, encoded)
        // These are literal protocol offsets, intentionally not DeviceIdentityBundle constants.
        assertEquals(0x00, encoded[26].toInt() and 0xFF)
        assertEquals(0x03, encoded[27].toInt() and 0xFF)
        assertEquals(0x04, encoded[31].toInt() and 0xFF)
        assertEquals(0xC2, encoded[32].toInt() and 0xFF)
        assertEquals(0x04, encoded[65].toInt() and 0xFF)
        assertEquals(0xA0, encoded[66].toInt() and 0xFF)
        assertEquals(0x07, encoded[1_251].toInt() and 0xFF)
        assertEquals(0xA0, encoded[1_252].toInt() and 0xFF)
        assertEquals(0x80, encoded[3_205].toInt() and 0xFF)
        assertEquals(0x05, encoded[3_208].toInt() and 0xFF)
        assertEquals(3_209, encoded.size)
    }

    @Test
    fun `rejects a hybrid public key whose embedded ML-KEM key is not 1184 bytes`() {
        val invalid = ByteArray(32 + 2 + 1_183) { 0x7A }.also {
            it[32] = 0x04
            it[33] = 0x9F.toByte()
        }

        val failure = assertFailsWith<InvalidDeviceIdentityKeyLength> {
            bundle(hybridPublicKey = invalid)
        }

        assertEquals(InvalidDeviceIdentityKeyLength.Key.ML_KEM, failure.key)
        assertEquals(1_184, failure.expectedBytes)
        assertEquals(1_183, failure.actualBytes)
    }

    @Test
    fun `rejects an ML-DSA public key that is not 1952 bytes`() {
        val failure = assertFailsWith<InvalidDeviceIdentityKeyLength> {
            bundle(mldsaPublicKey = ByteArray(1_951))
        }

        assertEquals(InvalidDeviceIdentityKeyLength.Key.ML_DSA, failure.key)
        assertEquals(1_952, failure.expectedBytes)
        assertEquals(1_951, failure.actualBytes)
    }

    @Test
    fun `safety number sorts bundles by their own digest before domain separated hashing`() {
        val local = bundle(rsaSpki = byteArrayOf(0x01))
        val peer = bundle(rsaSpki = byteArrayOf(0x02))
        val localDigest = ByteArray(32) { 0x7F }
        val peerDigest = ByteArray(32) { 0x01 }
        val combinedDigest = ByteArray(32) { it.toByte() }
        val expectedSafetyPreimage =
            "passman-device-safety-number-v1".encodeToByteArray() +
                peer.canonicalEncoding() + local.canonicalEncoding()
        val hash: (ByteArray) -> ByteArray = { bytes ->
            when {
                bytes.contentEquals(local.canonicalEncoding()) -> localDigest
                bytes.contentEquals(peer.canonicalEncoding()) -> peerDigest
                else -> {
                    assertContentEquals(expectedSafetyPreimage, bytes)
                    combinedDigest
                }
            }
        }

        val localFirst = local.safetyNumber(peer, hash)
        val peerFirst = peer.safetyNumber(local, hash)

        assertEquals("17807 31860 62770 00449 60722", localFirst)
        assertEquals(localFirst, peerFirst)
    }

    @Test
    fun `display name is outside the cryptographic identity and received reserved capabilities survive`() {
        val bundle = bundle(capabilityBits = 0x80000005u)
        val hash: (ByteArray) -> ByteArray = { bytes -> ByteArray(32) { bytes[it % bytes.size] } }
        val namedPairing = TrustedDevice(
            name = "laptop",
            fingerprint = "AB:CD",
            lastHost = "192.0.2.10",
            hybridPublicKey = "hybrid",
            mldsaPublicKey = "mldsa",
            identityDigest = "display digest",
            pairingSecurity = PairingSecurity.SignedHybridRequired,
        )
        val renamedPairing = namedPairing.copy(name = "new laptop name")
        val roundTripped = Json.decodeFromString<DeviceIdentityBundle>(Json.encodeToString(bundle))
        val local = DeviceIdentityBundle.local(
            rsaSpki = byteArrayOf(0x01),
            hybridPublicKey = hybridPublicKey(0x31),
            mldsaPublicKey = ByteArray(1_952) { 0x61 },
            supportedOps = setOf(SyncOps.PGP),
        )

        assertContentEquals(bundle.canonicalEncoding(), roundTripped.canonicalEncoding())
        assertContentEquals(bundle.digest(hash), roundTripped.digest(hash))
        assertEquals(bundle.safetyNumber(bundle, hash), roundTripped.safetyNumber(roundTripped, hash))
        assertEquals(0x80000005u, roundTripped.capabilityBits)
        assertEquals(DeviceIdentityBundle.CAPABILITY_PGP, local.capabilityBits)
        assertEquals("laptop", namedPairing.name)
        assertEquals("new laptop name", renamedPairing.name)
        assertFalse(Json.encodeToString(bundle).contains(namedPairing.name))
        assertFalse(Json.encodeToString(bundle).contains(renamedPairing.name))
    }

    @Test
    fun `legacy trusted device JSON receives secure pairing defaults without changing its TLS pin`() {
        val device = Json.decodeFromString<TrustedDevice>(
            """{"name":"desktop","fingerprint":"AA:BB","lastHost":"192.0.2.4"}""",
        )

        assertEquals("AA:BB", device.fingerprint)
        assertEquals(PairingSecurity.LegacyRsa, device.pairingSecurity)
        assertEquals(null, device.hybridPublicKey)
        assertEquals(null, device.mldsaPublicKey)
        assertEquals(null, device.identityDigest)
        assertTrue(device.allowedOps.isNotEmpty())
    }

    private fun bundle(
        rsaSpki: ByteArray = byteArrayOf(0x01, 0x02, 0x03),
        hybridPublicKey: ByteArray = hybridPublicKey(0x31),
        mldsaPublicKey: ByteArray = ByteArray(1_952) { 0x61 },
        capabilityBits: UInt = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
    ): DeviceIdentityBundle = DeviceIdentityBundle(
        rsaSpki = rsaSpki,
        hybridPublicKey = hybridPublicKey,
        mldsaPublicKey = mldsaPublicKey,
        capabilityBits = capabilityBits,
    )

    private fun hybridPublicKey(fill: Byte): ByteArray = ByteArray(32 + 2 + 1_184) { fill }.also {
        it[32] = 0x04
        it[33] = 0xA0.toByte()
    }
}
