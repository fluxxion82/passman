package ai.passman.viewvo.navigation

import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.domain.pgp.model.UserIdAction

sealed interface PgpDetailsNavigation
sealed interface PgpHomeNavigation
sealed interface PgpCreateKeyNavigation
sealed interface PgpAddUserIdNavigation
sealed interface PgpAddSubkeyNavigation
sealed interface PgpChangePasswordNavigation
sealed interface PgpDeleteKeyNavigation

data class PgpKeyDetails(val keyId: Long) : PgpHomeNavigation

data class AddUserId(val keyId: Long) : PgpDetailsNavigation
data class RevokeUserId(val keyId: Long, val userId: String, val action: UserIdAction): PgpDetailsNavigation
data class RemoveUserId(val keyId: Long, val userId: String, val action: UserIdAction): PgpDetailsNavigation
data class AddSubKey(val keyId: Long) : PgpDetailsNavigation
data class ModifySubKey(val keyId: Long, val subkeyId: String, val action: SubKeyAction): PgpDetailsNavigation
data class ChangePassword(val keyId: Long) : PgpDetailsNavigation
data class ChangeExpiryKey(val keyId: Long) : PgpDetailsNavigation
data class ChangeExpirySubKey(val keyId: Long) : PgpDetailsNavigation
data class PgpToolAction(val keyId: Long) : PgpDetailsNavigation
data class KeyDeleted(val keyId: Long) : PgpDetailsNavigation

data object DeleteSuccess: PgpDeleteKeyNavigation
