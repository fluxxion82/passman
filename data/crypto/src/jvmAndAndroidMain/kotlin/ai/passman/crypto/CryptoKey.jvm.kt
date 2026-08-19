package ai.passman.crypto

import java.security.Key

actual class CryptoKey(val key: Key) {
    actual val encoded: ByteArray get() = key.encoded
}
