package ai.passman.domain.password.totp

/**
 * RFC 4648 base32 decoding, the alphabet authenticator seeds use. Pure Kotlin because `domain`
 * compiles for JS and iOS where no platform codec exists.
 */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun decode(encoded: String): ByteArray {
        // Setup pages show secrets lowercase, spaced or dashed in groups; padding is often dropped.
        val cleaned = encoded.uppercase().filterNot { it == ' ' || it == '-' || it == '=' }
        val bytes = ArrayList<Byte>(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsHeld = 0
        for (char in cleaned) {
            val value = ALPHABET.indexOf(char)
            require(value >= 0) { "'$char' is not a base32 character" }
            buffer = (buffer shl 5) or value
            bitsHeld += 5
            if (bitsHeld >= 8) {
                bitsHeld -= 8
                bytes.add(((buffer shr bitsHeld) and 0xFF).toByte())
            }
        }
        return bytes.toByteArray()
    }
}
