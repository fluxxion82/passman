package ai.passman.domain.crypto.exception

import ai.passman.domain.exception.Failure

@Suppress("UnusedPrivateMember")
sealed class CryptoFailure {
    class GeneralAuthError(message: String, code: Int) : Failure.FeatureFailure()
    class CipherInitFailure(message: String) : Failure.FeatureFailure()
    object EncryptFailure : Failure.FeatureFailure()
    object DecryptFailure : Failure.FeatureFailure()
    object NotImplemented : Failure.FeatureFailure()
}
