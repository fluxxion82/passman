package ai.passman.domain.keystore.model

import kotlinx.serialization.Serializable

@Serializable
enum class KeystoreKeyAlgorithm {
    RSA,
    AES,
    UNKNOWN,
    ;
}
