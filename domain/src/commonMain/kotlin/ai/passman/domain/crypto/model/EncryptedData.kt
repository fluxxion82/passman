package ai.passman.domain.crypto.model

import kotlinx.serialization.Serializable

@Serializable
data class EncryptedData(val ciphertextOrPath: String, val cipherIv: String? = null)
