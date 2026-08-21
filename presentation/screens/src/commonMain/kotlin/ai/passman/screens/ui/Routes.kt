package ai.passman.screens.ui

import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.domain.pgp.model.UserIdAction
import kotlinx.serialization.Serializable

// ---- Onboard graph ----
@Serializable data object OnboardGraph
@Serializable data object Splash
@Serializable data object Login
@Serializable data object Signup

// ---- Top-level ----
@Serializable data object Home

// ---- Settings graph ----
@Serializable data object SettingsGraph
@Serializable data object Settings
@Serializable data object TransferPasswords
@Serializable data object ReconcileConflict
@Serializable data object TrustedDevicesRoute
@Serializable data object SyncActivityRoute
@Serializable data object PreservedCopiesRoute

// ---- PGP graph ----
@Serializable data object PgpGraph
@Serializable data object PgpHome
@Serializable data object CreatePgpKey

@Serializable data class PgpKeyDetails(val keyId: String)

@Serializable
data class PgpTools(val keyId: String, val actionOrdinal: Int, val isFileTarget: Boolean) {
    val action: CryptAction get() = CryptAction.entries[actionOrdinal]
    companion object {
        fun create(keyId: String, action: CryptAction, isFileTarget: Boolean) =
            PgpTools(keyId, action.ordinal, isFileTarget)
    }
}

@Serializable data class PgpAddUserId(val keyId: String)

@Serializable
data class PgpRemoveUserId(val keyId: String, val userId: String, val actionOrdinal: Int) {
    val action: UserIdAction get() = UserIdAction.entries[actionOrdinal]
    companion object {
        fun create(keyId: String, userId: String, action: UserIdAction) =
            PgpRemoveUserId(keyId, userId, action.ordinal)
    }
}

@Serializable data class PgpAddSubKey(val keyId: String)

@Serializable
data class PgpModifySubKey(val keyId: String, val subKeyId: String, val actionOrdinal: Int) {
    val action: SubKeyAction get() = SubKeyAction.entries[actionOrdinal]
    companion object {
        fun create(keyId: String, subKeyId: String, action: SubKeyAction) =
            PgpModifySubKey(keyId, subKeyId, action.ordinal)
    }
}

@Serializable data class PgpChangePassword(val keyId: String)
@Serializable data class PgpConfirmDelete(val keyId: String)

// ---- Password graph ----
@Serializable data object PasswordGraph
@Serializable data object PasswordHome
@Serializable data class PassEntryDetails(val passEntryUuid: String)
@Serializable data object AddPassEntry

// ---- Keystore graph ----
@Serializable data object KeystoreGraph
@Serializable data object KeystoreHome
@Serializable data object CreateKeystore

@Serializable data class KeystoreDetails(val keystorePath: String, val keystoreName: String)
@Serializable data class KeystoreAddKey(val keystorePath: String, val keystoreName: String)
@Serializable
data class KeystoreTools(
    val keystorePath: String,
    val keystoreName: String,
    val keyAlias: String,
    val actionOrdinal: Int,
    val isFileTarget: Boolean,
) {
    val action: CryptAction get() = CryptAction.entries[actionOrdinal]
    companion object {
        fun create(
            keystorePath: String,
            keystoreName: String,
            keyAlias: String,
            action: CryptAction,
            isFileTarget: Boolean,
        ) = KeystoreTools(keystorePath, keystoreName, keyAlias, action.ordinal, isFileTarget)
    }
}
