package ai.passman.domain.crypto.model

import ai.passman.domain.keystore.model.KeyStoreInfo

data class DecryptInfo(
    val keyStore: KeyStoreInfo,
    val keyAlias: String,
    val initializationVector: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (this::class != other!!::class) return false

        other as DecryptInfo

        if (keyStore != other.keyStore) return false
        if (keyAlias != other.keyAlias) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAlias.hashCode()
        result += 31 + keyStore.hashCode()
        result += 31 + initializationVector.contentHashCode()

        return result
    }
}
