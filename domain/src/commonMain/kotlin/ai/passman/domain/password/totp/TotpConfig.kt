package ai.passman.domain.password.totp

/**
 * A parsed TOTP seed. Accepts what users can actually paste: the raw base32 secret a setup page
 * shows, or the full `otpauth://totp/...` URI behind its QR code.
 */
class TotpConfig(
    val secret: ByteArray,
    val digits: Int = 6,
    val periodSeconds: Int = 30,
) {
    companion object {
        /**
         * The storage-friendly form of a pasted or scanned seed, or null when it does not parse.
         * A uri that carries only the RFC defaults collapses to its bare secret — that is what
         * users expect to see in the field — while non-default parameters keep the full uri, the
         * only place those parameters survive.
         */
        fun normalizeSeed(input: String): String? {
            val trimmed = input.trim()
            val config = runCatching { parse(trimmed) }.getOrNull() ?: return null
            if (!trimmed.startsWith("otpauth://", ignoreCase = true)) return trimmed
            if (config.digits != 6 || config.periodSeconds != 30) return trimmed
            return trimmed.substringAfter('?', missingDelimiterValue = "")
                .split('&')
                .firstNotNullOfOrNull { param ->
                    param.substringAfter('=', missingDelimiterValue = "")
                        .takeIf { param.substringBefore('=').equals("secret", ignoreCase = true) }
                }
                ?.takeIf { it.isNotEmpty() }
        }

        fun parse(input: String): TotpConfig {
            val trimmed = input.trim()
            require(trimmed.isNotEmpty()) { "TOTP seed is empty" }
            if (!trimmed.startsWith("otpauth://", ignoreCase = true)) {
                val secret = Base32.decode(trimmed)
                require(secret.isNotEmpty()) { "TOTP seed is empty" }
                return TotpConfig(secret)
            }

            val afterScheme = trimmed.substring("otpauth://".length)
            val type = afterScheme.substringBefore('/').lowercase()
            require(type == "totp") { "only totp is supported, not $type" }

            val query = afterScheme.substringAfter('?', missingDelimiterValue = "")
            val params = query.split('&')
                .mapNotNull { param ->
                    val key = param.substringBefore('=')
                    val value = param.substringAfter('=', missingDelimiterValue = "")
                    if (key.isEmpty() || value.isEmpty()) null else key.lowercase() to value
                }
                .toMap()

            val secretParam = params["secret"]
            require(!secretParam.isNullOrEmpty()) { "the uri has no secret parameter" }
            params["algorithm"]?.let { algorithm ->
                require(algorithm.equals("SHA1", ignoreCase = true)) { "unsupported algorithm $algorithm" }
            }
            val digits = params["digits"]?.let {
                requireNotNull(it.toIntOrNull()) { "digits is not a number: $it" }
            } ?: 6
            require(digits in 6..8) { "digits must be 6..8, was $digits" }
            val period = params["period"]?.let {
                requireNotNull(it.toIntOrNull()) { "period is not a number: $it" }
            } ?: 30
            require(period > 0) { "period must be positive, was $period" }

            return TotpConfig(Base32.decode(secretParam), digits, period)
        }
    }
}
