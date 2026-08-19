package ai.passman.domain.user.exception

import ai.passman.domain.exception.Failure

sealed class ForgotPasswordFailure {
    class GeneralResetPassFailure(val message: String?) : Failure.FeatureFailure()
}
