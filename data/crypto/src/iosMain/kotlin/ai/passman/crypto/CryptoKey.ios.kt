package ai.passman.crypto

actual class CryptoKey(internal val opaque: Any?) {
    actual val encoded: ByteArray
        get() = error("CryptoKey.encoded not implemented on iOS")
}
