package ai.passman.domain.pgp.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// trust, validity
@Serializable
data class PgpKey(
    val fileName: String,
    val path: String,
    val type: PgpKeyType,
    val keyId: Long,
    val creationTime: Long,
    val expirationTime: Long?,
    val isRevoked: Boolean,
    val algorithm: String, // PublicKeyAlgorithmTags
    val bitStrength: Int,
    val userIds: List<UserId>,
    val fingerprint: String,
    val isMaster: Boolean,
    val isSigningKey: Boolean,
    val isEncryptionKey: Boolean,
    val isEncrypted: Boolean = false, // only relevant for secret  keys
    val subKeys: List<PgpKey> = listOf(),
)

// The @SerialName values are stable identifiers: without them the sealed-class discriminator
// defaults to the fully qualified class name, which ends up inside persisted pgp_prefs JSON
// and breaks on any package rename (LocalPgpPreferences migrates the pre-rename spellings).
@Serializable
sealed interface PgpKeyType {
    @Serializable
    @SerialName("secret")
    data object Secret : PgpKeyType

    @Serializable
    @SerialName("public")
    data object Public : PgpKeyType
}
