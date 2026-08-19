package ai.passman.domain.keystore.exception

import ai.passman.domain.exception.Failure

sealed class KeystoreFailure {
    data object NotFound : Failure.FeatureFailure()
    data object KeyNotFound : Failure.FeatureFailure()
    data object GetAliasesFailure : Failure.FeatureFailure()
    data object CreateKeystore : Failure.FeatureFailure()
    data object KeyGenerationFailure : Failure.FeatureFailure()
    data object ChangePasswordFailure : Failure.FeatureFailure()
}
