package ai.passman.domain.keystore.model

import kotlinx.serialization.Serializable

@Serializable
data class KeyStoreInfo(
    val path: String,
    val name: String,
    val keystorePassword: String,
    val keyList: List<KeystoreKey>,
    val type: KeyStoreType
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (this::class != other!!::class) return false

        other as KeyStoreInfo

        if (path != other.path) return false
        if (name != other.name) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = path.hashCode()
        result += 31 + name.hashCode()
        result += 31 + type.type.hashCode()

        return result
    }
}

@Serializable
enum class KeyStoreType(val type: String) {
    ANDROID("AndroidKeyStore"),
    PKCS12("PKCS12"),
    BKS("BKS"),
    JKS("JKS")
}
