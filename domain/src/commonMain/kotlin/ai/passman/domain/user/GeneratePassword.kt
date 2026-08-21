package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Generates a random password from the requested character sets.
 *
 * ## Randomness
 *
 * The characters are drawn from a cryptographically secure source. The passwords this produces
 * guard real artifacts (the auto-provisioned keystore and PGP ring passphrases among them), and the
 * previous implementation's `Random.Default` is a plain xorshift whose entire future output can be
 * reconstructed from a handful of observed values. `domain` is common code with no
 * `java.security.SecureRandom` in reach, and the standard library's one multiplatform CSPRNG is
 * [Uuid.random] — each v4 UUID carries 15.25 bytes of CSPRNG output. [SecureByteStream] taps that
 * rather than introducing an expect/actual seam for a single call site.
 *
 * ## Uniformity
 *
 * A byte is mapped to a character by rejection sampling: bytes at or above the largest multiple of
 * `alphabet.size` that fits in 256 are discarded instead of wrapped, because wrapping (`byte %
 * size`) makes the low alphabet indices measurably more likely. The loop consumes a fresh byte per
 * attempt, so every emitted character is uniform over the alphabet.
 */
class GeneratePassword : Usecase<GeneratePassword.PasswordInfo, String> {

    enum class CharSet {
        SYMBOLS, UPPERCASE, LOWERCASE, NUMBER
    }

    data class PasswordInfo(val charSet: Set<CharSet>, val passLength: Int)

    override suspend fun invoke(param: PasswordInfo): String {
        val alphabet = buildString {
            param.charSet.forEach {
                append(
                    when (it) {
                        CharSet.UPPERCASE -> UPPER
                        CharSet.LOWERCASE -> LOWER
                        CharSet.NUMBER -> NUM
                        CharSet.SYMBOLS -> SYMBOLS
                    },
                )
            }
        }
        if (alphabet.isEmpty() || param.passLength <= 0) return ""

        val bytes = SecureByteStream()
        // Largest multiple of the alphabet size that fits in a byte; everything at or above it is
        // rejected so that no character is more likely than another.
        val acceptBelow = 256 - 256 % alphabet.length
        val generated = StringBuilder(param.passLength)
        while (generated.length < param.passLength) {
            val byte = bytes.next()
            if (byte < acceptBelow) generated.append(alphabet[byte % alphabet.length])
        }
        return generated.toString()
    }

    /**
     * A stream of uniform random bytes backed by [Uuid.random], the standard library's CSPRNG.
     *
     * A version-4 UUID is 16 CSPRNG bytes with two of them partially overwritten: byte 6's high
     * nibble is the fixed version (`0100`) and byte 8's top two bits are the fixed variant (`10`).
     * Those two bytes are dropped entirely — simpler than salvaging their remaining bits, and it
     * keeps every byte this stream hands out fully uniform over 0..255.
     */
    @OptIn(ExperimentalUuidApi::class)
    private class SecureByteStream {
        private var buffer = ByteArray(0)
        private var index = 0

        fun next(): Int {
            if (index >= buffer.size) refill()
            return buffer[index++].toInt() and 0xFF
        }

        private fun refill() {
            val raw = Uuid.random().toByteArray()
            val clean = ByteArray(CLEAN_BYTES_PER_UUID)
            var out = 0
            for (i in raw.indices) {
                if (i != VERSION_BYTE && i != VARIANT_BYTE) clean[out++] = raw[i]
            }
            buffer = clean
            index = 0
        }

        private companion object {
            const val VERSION_BYTE = 6
            const val VARIANT_BYTE = 8
            const val CLEAN_BYTES_PER_UUID = 14
        }
    }

    companion object {
        const val SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_{|}~"
        const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        const val LOWER = "abcdefghijklmnopqrstuvwxyz"
        const val NUM = "0123456789"

        /**
         * The shape used for a machine-generated secret that a human still has to handle: high
         * entropy — 24 characters over a 93-character alphabet is ~157 bits — but still something
         * a user can read out of their vault and type into an unlock prompt. Nothing on the
         * signup or login path mints one any more; it stays as the reference shape (and is what
         * `PgpClient.PROVISIONED_RING_S2K_COUNT` assumes about a passphrase it is not stretching).
         */
        val PROVISIONED_SECRET = PasswordInfo(
            charSet = setOf(CharSet.UPPERCASE, CharSet.LOWERCASE, CharSet.NUMBER, CharSet.SYMBOLS),
            passLength = 24,
        )

    }
}
