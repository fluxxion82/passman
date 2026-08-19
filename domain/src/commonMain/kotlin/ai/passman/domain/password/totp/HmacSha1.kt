package ai.passman.domain.password.totp

/**
 * HMAC-SHA1 (RFC 2104) over a pure-Kotlin SHA-1 (RFC 3174). Written out by hand because `domain`
 * compiles for JS and iOS, where neither JCA nor BouncyCastle exists, and RFC 6238 mandates SHA-1
 * as the default TOTP algorithm. SHA-1's collision weakness is irrelevant here — HMAC only needs
 * second-preimage resistance.
 */
object HmacSha1 {
    private const val BLOCK_SIZE = 64

    fun compute(key: ByteArray, message: ByteArray): ByteArray {
        val reduced = if (key.size > BLOCK_SIZE) Sha1.digest(key) else key
        val padded = reduced.copyOf(BLOCK_SIZE)
        val inner = ByteArray(BLOCK_SIZE) { (padded[it].toInt() xor 0x36).toByte() }
        val outer = ByteArray(BLOCK_SIZE) { (padded[it].toInt() xor 0x5c).toByte() }
        return Sha1.digest(outer + Sha1.digest(inner + message))
    }
}

internal object Sha1 {
    fun digest(message: ByteArray): ByteArray {
        val bitLength = message.size.toLong() * 8
        val paddedLength = ((message.size + 8) / 64 + 1) * 64
        val padded = message.copyOf(paddedLength)
        padded[message.size] = 0x80.toByte()
        for (i in 0 until 8) {
            padded[paddedLength - 1 - i] = ((bitLength shr (8 * i)) and 0xFF).toByte()
        }

        var h0 = 0x67452301
        var h1 = 0xEFCDAB89.toInt()
        var h2 = 0x98BADCFE.toInt()
        var h3 = 0x10325476
        var h4 = 0xC3D2E1F0.toInt()

        val w = IntArray(80)
        for (chunk in 0 until paddedLength step 64) {
            for (i in 0 until 16) {
                w[i] = ((padded[chunk + 4 * i].toInt() and 0xFF) shl 24) or
                    ((padded[chunk + 4 * i + 1].toInt() and 0xFF) shl 16) or
                    ((padded[chunk + 4 * i + 2].toInt() and 0xFF) shl 8) or
                    (padded[chunk + 4 * i + 3].toInt() and 0xFF)
            }
            for (i in 16 until 80) {
                w[i] = (w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]).rotateLeft(1)
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            for (i in 0 until 80) {
                val (f, k) = when {
                    i < 20 -> ((b and c) or (b.inv() and d)) to 0x5A827999
                    i < 40 -> (b xor c xor d) to 0x6ED9EBA1
                    i < 60 -> ((b and c) or (b and d) or (c and d)) to 0x8F1BBCDC.toInt()
                    else -> (b xor c xor d) to 0xCA62C1D6.toInt()
                }
                val temp = a.rotateLeft(5) + f + e + k + w[i]
                e = d
                d = c
                c = b.rotateLeft(30)
                b = a
                a = temp
            }
            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
        }

        val out = ByteArray(20)
        intArrayOf(h0, h1, h2, h3, h4).forEachIndexed { index, word ->
            out[4 * index] = ((word shr 24) and 0xFF).toByte()
            out[4 * index + 1] = ((word shr 16) and 0xFF).toByte()
            out[4 * index + 2] = ((word shr 8) and 0xFF).toByte()
            out[4 * index + 3] = (word and 0xFF).toByte()
        }
        return out
    }
}
