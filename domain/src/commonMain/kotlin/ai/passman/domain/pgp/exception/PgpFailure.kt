package ai.passman.domain.pgp.exception

import ai.passman.domain.exception.Failure

sealed class PgpFailure : Failure.FeatureFailure() {
    class GeneralPgpError(message: String) : FeatureFailure()
    data object ImportKeyFailure : FeatureFailure()

    /**
     * The file is a real OpenPGP key ring, but a key or subkey in it uses [algorithmId], which this
     * build cannot use. Separate from [ImportKeyFailure] because the cause is the algorithm rather
     * than the file, and naming the id is the only way the user can find out what to do about it.
     *
     * Not a data class: [Failure] members here are compared by identity elsewhere, and a data
     * class's `equals` would quietly change that for this one member.
     */
    class UnsupportedKeyAlgorithm(val algorithmId: Int) : FeatureFailure()
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
    data object SharePublicKeyFailure : FeatureFailure()
    data object ExportPrivateKeyFailure : FeatureFailure()
}
