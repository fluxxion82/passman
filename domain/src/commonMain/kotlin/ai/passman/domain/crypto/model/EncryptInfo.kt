package ai.passman.domain.crypto.model

import ai.passman.domain.keystore.model.KeyStoreInfo

data class EncryptInfo(val keyStore: KeyStoreInfo, val keyAlias: String) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (this::class != other!!::class) return false

        other as EncryptInfo

        if (keyStore != other.keyStore) return false
        if (keyAlias != other.keyAlias) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAlias.hashCode()
        result += 31 + keyAlias.hashCode()

        return result
    }
}
