package ai.passman.crypto.model

import ai.passman.crypto.util.ByteArrayAsBase64Serializer
import kotlinx.serialization.Serializable

@Serializable
data class EncryptedData(
    @Serializable(with = ByteArrayAsBase64Serializer::class) val encryptedMessage: ByteArray,
    @Serializable(with = ByteArrayAsBase64Serializer::class) val encryptedKey: ByteArray,
    @Serializable(with = ByteArrayAsBase64Serializer::class) val iv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass !== other?.javaClass) return false

        other as EncryptedData

        if (!encryptedMessage.contentEquals(other.encryptedMessage)) return false
        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!iv.contentEquals(other.iv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = encryptedMessage.contentHashCode()
        result = 31 * result + encryptedKey.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        return result
    }
}
