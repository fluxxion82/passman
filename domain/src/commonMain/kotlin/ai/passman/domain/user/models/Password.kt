package ai.passman.domain.user.models

import kotlinx.serialization.Serializable

/** [kdf] describes how [hash] was derived; null means the pre-versioning legacy PBKDF2 params. */
@Serializable
data class Password(val hash: String, val salt: String, val kdf: KdfParams? = null)
