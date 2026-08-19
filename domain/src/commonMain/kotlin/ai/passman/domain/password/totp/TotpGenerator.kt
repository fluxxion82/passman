package ai.passman.domain.password.totp

/** HOTP (RFC 4226) and TOTP (RFC 6238) over [HmacSha1]. */
object TotpGenerator {
    fun code(secret: ByteArray, epochSeconds: Long, periodSeconds: Int = 30, digits: Int = 6): String =
        hotp(secret, epochSeconds / periodSeconds, digits)

    fun secondsRemaining(epochSeconds: Long, periodSeconds: Int = 30): Int =
        (periodSeconds - (epochSeconds % periodSeconds)).toInt()

    fun hotp(secret: ByteArray, counter: Long, digits: Int): String {
        val message = ByteArray(8) { ((counter shr (8 * (7 - it))) and 0xFF).toByte() }
        val mac = HmacSha1.compute(secret, message)
        val offset = mac.last().toInt() and 0x0F
        val binary = ((mac[offset].toInt() and 0x7F) shl 24) or
            ((mac[offset + 1].toInt() and 0xFF) shl 16) or
            ((mac[offset + 2].toInt() and 0xFF) shl 8) or
            (mac[offset + 3].toInt() and 0xFF)
        var divisor = 1
        repeat(digits) { divisor *= 10 }
        return (binary % divisor).toString().padStart(digits, '0')
    }
}
