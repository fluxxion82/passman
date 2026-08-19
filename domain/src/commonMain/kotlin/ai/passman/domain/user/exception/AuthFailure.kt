package ai.passman.domain.user.exception

import ai.passman.domain.exception.Failure

sealed class AuthFailure {
    object SignupFailure : Failure.FeatureFailure()
    object LoginFailure : Failure.FeatureFailure()
    data class GeneralAuthFailure(val message: String?) : Failure.FeatureFailure()
    data class ServerError(val message: String?) : Failure.FeatureFailure()
    object InvalidPassword : Failure.FeatureFailure()
    object NoStoredCredentials : Failure.FeatureFailure()
    object BioAuthFailed : Failure.FeatureFailure()
    object AccountAlreadyExists : Failure.FeatureFailure()
    object KeystoreCreationFailure : Failure.FeatureFailure()
    object PgpKeyRingCreationFailure : Failure.FeatureFailure()
}
