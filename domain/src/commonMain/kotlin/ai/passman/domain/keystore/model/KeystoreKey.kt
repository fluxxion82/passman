package ai.passman.domain.keystore.model

import kotlinx.serialization.Serializable

@Serializable
data class KeystoreKey(
    val keyAlias: String,
    val keyPassword: String,
    val keyAlgorithm: KeystoreKeyAlgorithm,
)
