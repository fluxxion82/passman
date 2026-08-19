package ai.passman.domain.connectivity.model

import ai.passman.domain.connectivity.service.FingerprintService
import kotlinx.serialization.Serializable

/**
 * Public cryptographic identity exchanged while pairing a device.
 *
 * This deliberately contains no user-supplied display name. A name is local pairing metadata and
 * changing it must never change the cryptographic identity a peer verifies.
 */
@Serializable
data class DeviceIdentityBundle(
    val rsaSpki: ByteArray,
    /** `x25519(32) | mlKemLength(2, BE) | mlKem(1184)`, matching EnvelopeCodec's wire form. */
    val hybridPublicKey: ByteArray,
    val mldsaPublicKey: ByteArray,
    /** Raw received bits are retained so future capabilities do not change the identity digest. */
    val capabilityBits: UInt,
) {
    init {
        validateKeyLengths()
        require(rsaSpki.size <= MAX_U16) { "RSA SPKI is too large for the identity bundle" }
    }

    /**
     * Pure, cross-platform preimage for the composite device identity digest.
     *
     * Hashing this byte sequence is intentionally delegated to [FingerprintService] implementations
     * by callers because domain commonMain has no portable digest primitive.
     */
    fun canonicalEncoding(): ByteArray {
        // Byte arrays are mutable, so re-check them in case a caller changed one after construction.
        validateKeyLengths()
        require(rsaSpki.size <= MAX_U16) { "RSA SPKI is too large for the identity bundle" }

        val out = ByteArray(
            IDENTITY_DOMAIN.size + U16_BYTES + rsaSpki.size + U16_BYTES + hybridPublicKey.size +
                U16_BYTES + mldsaPublicKey.size + U32_BYTES,
        )
        var offset = 0
        IDENTITY_DOMAIN.copyInto(out, offset)
        offset += IDENTITY_DOMAIN.size
        offset = writeU16(out, offset, rsaSpki.size)
        rsaSpki.copyInto(out, offset)
        offset += rsaSpki.size
        offset = writeU16(out, offset, hybridPublicKey.size)
        hybridPublicKey.copyInto(out, offset)
        offset += hybridPublicKey.size
        offset = writeU16(out, offset, mldsaPublicKey.size)
        mldsaPublicKey.copyInto(out, offset)
        offset += mldsaPublicKey.size
        writeU32(out, offset, capabilityBits)
        return out
    }

    /** Compute this bundle's digest through a platform-provided hash implementation. */
    fun digest(hash: (ByteArray) -> ByteArray): ByteArray = hash(canonicalEncoding())

    /** Compute this bundle's digest through the platform seam used by pairing callers. */
    fun digest(fingerprintService: FingerprintService): ByteArray = digest(fingerprintService::digest)

    /**
     * A symmetric human-comparison value. The two canonical bundles are ordered by their own digests
     * before the final, domain-separated digest, so both devices display exactly the same number.
     */
    fun safetyNumber(peer: DeviceIdentityBundle, hash: (ByteArray) -> ByteArray): String {
        val ours = canonicalEncoding()
        val theirs = peer.canonicalEncoding()
        val first: ByteArray
        val second: ByteArray
        if (compareUnsigned(hash(ours), hash(theirs)) <= 0) {
            first = ours
            second = theirs
        } else {
            first = theirs
            second = ours
        }
        val combined = SAFETY_NUMBER_DOMAIN + first + second
        return groupedDecimal(hash(combined))
    }

    /** Compute the symmetric safety number through the platform digest seam. */
    fun safetyNumber(peer: DeviceIdentityBundle, fingerprintService: FingerprintService): String =
        safetyNumber(peer, fingerprintService::digest)

    /** Known capabilities only; reserved bits are therefore always zero on locally-created bundles. */
    fun supports(operation: String): Boolean = when (operation) {
        SyncOps.PASSWORDS -> capabilityBits and CAPABILITY_PASSWORDS != 0u
        SyncOps.PGP -> capabilityBits and CAPABILITY_PGP != 0u
        SyncOps.KEYSTORE -> capabilityBits and CAPABILITY_KEYSTORE != 0u
        else -> false
    }

    private fun validateKeyLengths() {
        val embeddedMlKemLength = if (hybridPublicKey.size >= HYBRID_ML_KEM_LENGTH_OFFSET + U16_BYTES) {
            readU16(hybridPublicKey, HYBRID_ML_KEM_LENGTH_OFFSET)
        } else {
            -1
        }
        if (embeddedMlKemLength != ML_KEM_PUBLIC_KEY_BYTES) {
            throw InvalidDeviceIdentityKeyLength(
                key = InvalidDeviceIdentityKeyLength.Key.ML_KEM,
                expectedBytes = ML_KEM_PUBLIC_KEY_BYTES,
                actualBytes = embeddedMlKemLength,
            )
        }
        if (hybridPublicKey.size != HYBRID_ML_KEM_BYTES_OFFSET + embeddedMlKemLength) {
            throw InvalidDeviceIdentityKeyLength(
                key = InvalidDeviceIdentityKeyLength.Key.HYBRID,
                expectedBytes = HYBRID_ML_KEM_BYTES_OFFSET + embeddedMlKemLength,
                actualBytes = hybridPublicKey.size,
            )
        }
        if (mldsaPublicKey.size != ML_DSA_PUBLIC_KEY_BYTES) {
            throw InvalidDeviceIdentityKeyLength(
                key = InvalidDeviceIdentityKeyLength.Key.ML_DSA,
                expectedBytes = ML_DSA_PUBLIC_KEY_BYTES,
                actualBytes = mldsaPublicKey.size,
            )
        }
    }

    companion object {
        private val IDENTITY_DOMAIN = "passman-device-identity-v1".encodeToByteArray()
        private val SAFETY_NUMBER_DOMAIN = "passman-device-safety-number-v1".encodeToByteArray()
        private const val U16_BYTES = 2
        private const val U32_BYTES = 4
        private const val MAX_U16 = 0xFFFF
        private const val HYBRID_ML_KEM_LENGTH_OFFSET = 32
        private const val HYBRID_ML_KEM_BYTES_OFFSET = HYBRID_ML_KEM_LENGTH_OFFSET + U16_BYTES
        private const val ML_KEM_PUBLIC_KEY_BYTES = 1_184
        private const val ML_DSA_PUBLIC_KEY_BYTES = 1_952

        private fun readU16(bytes: ByteArray, offset: Int): Int =
            ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

        private fun writeU16(out: ByteArray, offset: Int, value: Int): Int {
            out[offset] = (value ushr 8).toByte()
            out[offset + 1] = value.toByte()
            return offset + U16_BYTES
        }

        private fun writeU32(out: ByteArray, offset: Int, value: UInt) {
            out[offset] = (value shr 24).toByte()
            out[offset + 1] = (value shr 16).toByte()
            out[offset + 2] = (value shr 8).toByte()
            out[offset + 3] = value.toByte()
        }

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            val count = minOf(left.size, right.size)
            for (index in 0 until count) {
                val difference = (left[index].toInt() and 0xFF) - (right[index].toInt() and 0xFF)
                if (difference != 0) return difference
            }
            return left.size - right.size
        }

        private fun groupedDecimal(bytes: ByteArray): String {
            val digits = mutableListOf(0)
            for (byte in bytes) {
                var carry = byte.toInt() and 0xFF
                for (index in digits.lastIndex downTo 0) {
                    val value = digits[index] * 256 + carry
                    digits[index] = value % 10
                    carry = value / 10
                }
                while (carry > 0) {
                    digits.add(0, carry % 10)
                    carry /= 10
                }
            }
            val firstTwentyFive = digits.joinToString(separator = "").padStart(SAFETY_DIGITS, '0').take(SAFETY_DIGITS)
            return firstTwentyFive.chunked(SAFETY_GROUP_SIZE).joinToString(" ")
        }
        const val CAPABILITY_PASSWORDS: UInt = 0x1u
        const val CAPABILITY_PGP: UInt = 0x2u
        const val CAPABILITY_KEYSTORE: UInt = 0x4u

        /** Create a local bundle; unlike decoded peer bundles, it never transmits reserved bits. */
        fun local(
            rsaSpki: ByteArray,
            hybridPublicKey: ByteArray,
            mldsaPublicKey: ByteArray,
            supportedOps: Set<String> = SyncOps.ALL,
        ): DeviceIdentityBundle = DeviceIdentityBundle(
            rsaSpki = rsaSpki,
            hybridPublicKey = hybridPublicKey,
            mldsaPublicKey = mldsaPublicKey,
            capabilityBits = capabilityBitsFor(supportedOps),
        )

        fun capabilityBitsFor(operations: Set<String>): UInt =
            (if (SyncOps.PASSWORDS in operations) CAPABILITY_PASSWORDS else 0u) or
                (if (SyncOps.PGP in operations) CAPABILITY_PGP else 0u) or
                (if (SyncOps.KEYSTORE in operations) CAPABILITY_KEYSTORE else 0u)

        private const val SAFETY_DIGITS = 25
        private const val SAFETY_GROUP_SIZE = 5
    }
}

/** Structured validation failure so callers can distinguish an ML-KEM from an ML-DSA mismatch. */
class InvalidDeviceIdentityKeyLength(
    val key: Key,
    val expectedBytes: Int,
    val actualBytes: Int,
) : IllegalArgumentException("$key public key must be $expectedBytes bytes, was $actualBytes") {
    enum class Key { HYBRID, ML_KEM, ML_DSA }
}
