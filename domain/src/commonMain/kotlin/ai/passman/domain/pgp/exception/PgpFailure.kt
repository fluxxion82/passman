package ai.passman.domain.pgp.exception

import ai.passman.domain.exception.Failure

sealed class PgpFailure : Failure.FeatureFailure() {
    class GeneralPgpError(message: String) : FeatureFailure()
    data object ImportKeyFailure : FeatureFailure()
    data object EncryptFailure : FeatureFailure()
    data object DecryptFailure : FeatureFailure()
    data object WrongPassword : FeatureFailure()
    data object SignFailure : FeatureFailure()
    data object SignAndEncryptFailure : FeatureFailure()
    data object DecryptAndVerifyFailure : FeatureFailure()
    data object SignVerifyFailure : FeatureFailure()
    data object AddUserIdFailure : FeatureFailure()
    data object RevokeUserIdFailure : FeatureFailure()
    data object RemoveUserIdFailure : FeatureFailure()
    data object AddSubKeyFailure : FeatureFailure()
    data object RemoveSubKeyFailure : FeatureFailure()
    data object RevokeSubKeyFailure : FeatureFailure()
    data object ChangePasswordFailure : FeatureFailure()
    data object DeleteKeyPairFailure : FeatureFailure()

    /**
     * `createDefaultKeyRings` refused because a non-empty file already sits under a default ring
     * name. Distinguished from a generic creation failure because the condition is permanent:
     * the caller flags the account as settled instead of re-failing on every login.
     */
    data object DefaultRingsOccupied : FeatureFailure()
    data object SharePublicKeyFailure : FeatureFailure()
    data object ExportPrivateKeyFailure : FeatureFailure()
}
