package ai.passman.domain.connectivity.model

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The QR/pairing-code payload: enough for a peer to reach this device's pairing listener and
 * cryptographically verify the identity bundle it fetches, plus a single-use nonce whose
 * possession proves the peer physically saw the QR. Key material never rides in it.
 */
@OptIn(ExperimentalEncodingApi::class)
class PairingQrPayload(
    val host: String,
    val port: Int,
    digest: ByteArray,
    nonce: ByteArray,
) {
    val digest: ByteArray = digest.copyOf()
        get() = field.copyOf()
    val nonce: ByteArray = nonce.copyOf()
        get() = field.copyOf()

    init {
        require(host.isNotBlank() && host.all { it.isLetterOrDigit() || it in HOST_PUNCTUATION }) { "invalid host" }
        require(port in 1..MAX_PORT) { "invalid port" }
        require(digest.size == DIGEST_BYTES) { "digest must be $DIGEST_BYTES bytes" }
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
    }

    /**
     * The canonical wire form rendered into the QR: scheme, version, then `host`, `port`, `digest`
     * and `nonce` in that fixed order. Byte parameters are unpadded base64url, so the string stays
     * inside the QR alphanumeric budget and one payload always encodes to exactly one string.
     */
    fun encode(): String =
        "$SCHEME$VERSION?$PARAM_HOST=$host&$PARAM_PORT=$port" +
            "&$PARAM_DIGEST=${B64.encode(digest)}&$PARAM_NONCE=${B64.encode(nonce)}"

    /**
     * Equality is by content, not identity, so a decoded payload compares equal to the one that was
     * encoded. Hand-written because a data class would hand the scanner's nonce to `toString()`.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PairingQrPayload) return false
        return host == other.host &&
            port == other.port &&
            digest.contentEquals(other.digest) &&
            nonce.contentEquals(other.nonce)
    }

    override fun hashCode(): Int {
        var result = host.hashCode()
        result = 31 * result + port
        result = 31 * result + digest.contentHashCode()
        result = 31 * result + nonce.contentHashCode()
        return result
    }

    sealed interface ParseResult {
        /** A structurally valid pairing code. The peer it names may still be unreachable or stale. */
        data class Parsed(val payload: PairingQrPayload) : ParseResult

        /** Not ours at all — a TOTP QR, a URL, arbitrary text. */
        data object NotPairingCode : ParseResult

        /** Ours, but unusable. Callers own the wording; the domain only classifies the failure. */
        data class Malformed(val reason: Reason) : ParseResult

        enum class Reason {
            /** The scheme is ours but the version is not one this build knows how to read. */
            UNSUPPORTED_VERSION,

            /** A required part of the code is absent — usually a partial or truncated scan. */
            INCOMPLETE,

            /** Every required part is present but at least one of them does not hold up. */
            INVALID,
        }
    }

    companion object {
        /** The port a device's pairing listener binds by default, and what a QR carries unless moved. */
        const val DEFAULT_PAIRING_PORT = 2324
        private const val SCHEME = "passman-pair:"
        private const val VERSION = "v1"
        private const val DIGEST_BYTES = 32
        private const val NONCE_BYTES = 32
        private const val MAX_PORT = 65535
        private const val MAX_PORT_DIGITS = 5
        private const val PARAM_HOST = "host"
        private const val PARAM_PORT = "port"
        private const val PARAM_DIGEST = "digest"
        private const val PARAM_NONCE = "nonce"

        /** Hostnames, IPv4 dotted quads and bracketed IPv6 literals, and nothing that could re-delimit. */
        private const val HOST_PUNCTUATION = ".-:[]"
        private val B64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        /**
         * Whether [text] is even addressed to us, so a scanner can route a code to [parse] instead of
         * its other handlers without hardcoding the scheme.
         */
        fun looksLikePairingCode(text: String): Boolean = text.trim().startsWith(SCHEME, ignoreCase = true)

        /**
         * Read a scanned or pasted pairing code.
         *
         * This validates shape only — that the scheme, version and four required parameters are
         * present and well-formed. It says nothing about whether the host is reachable, the nonce
         * still live, or the digest one this device should trust; those are the pairing handshake's
         * job. The scheme, version and parameter names are matched case-insensitively because QR
         * encoders may uppercase to reach the alphanumeric mode, while parameter values are not.
         * Unknown extra parameters are tolerated so a newer device's code still pairs with this one.
         */
        fun parse(text: String): ParseResult {
            val trimmed = text.trim()
            if (!trimmed.startsWith(SCHEME, ignoreCase = true)) return ParseResult.NotPairingCode
            val rest = trimmed.substring(SCHEME.length)
            val version = rest.substringBefore('?', missingDelimiterValue = rest).lowercase()
            if (version.isEmpty()) return ParseResult.Malformed(ParseResult.Reason.INCOMPLETE)
            if (version != VERSION) return ParseResult.Malformed(ParseResult.Reason.UNSUPPORTED_VERSION)
            if ('?' !in rest) return ParseResult.Malformed(ParseResult.Reason.INCOMPLETE)

            val pairs = rest.substringAfter('?')
                .split('&')
                .mapNotNull { param ->
                    val key = param.substringBefore('=', missingDelimiterValue = "")
                    if (key.isEmpty() || '=' !in param) null else key.lowercase() to param.substringAfter('=')
                }
            val params = pairs.toMap()
            // A repeated key means two readings of the same field; never guess which one was meant.
            if (params.size != pairs.size) return ParseResult.Malformed(ParseResult.Reason.INVALID)

            val host = params[PARAM_HOST].orEmpty()
            val rawPort = params[PARAM_PORT]
            val rawDigest = params[PARAM_DIGEST]
            val rawNonce = params[PARAM_NONCE]
            if (host.isBlank() || rawPort == null || rawDigest == null || rawNonce == null) {
                return ParseResult.Malformed(ParseResult.Reason.INCOMPLETE)
            }
            val port = canonicalPort(rawPort) ?: return ParseResult.Malformed(ParseResult.Reason.INVALID)
            return try {
                ParseResult.Parsed(PairingQrPayload(host, port, B64.decode(rawDigest), B64.decode(rawNonce)))
            } catch (_: IllegalArgumentException) {
                ParseResult.Malformed(ParseResult.Reason.INVALID)
            }
        }

        /**
         * Plain decimal digits only: no sign, no leading zeros, no non-ASCII digits, so a given
         * listener has exactly one spelling in the wire form.
         */
        private fun canonicalPort(raw: String): Int? {
            if (raw.length !in 1..MAX_PORT_DIGITS) return null
            if (raw[0] !in '1'..'9') return null
            if (!raw.all { it in '0'..'9' }) return null
            return raw.toIntOrNull()
        }
    }
}
