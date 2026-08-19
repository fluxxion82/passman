package ai.passman.viewvo.signup

sealed class SignUpNavigation {
    data object MissingInformation : SignUpNavigation()
    data class InvalidCredentials(val message: String) : SignUpNavigation()
    data object AccountExists : SignUpNavigation()
    data class SignupError(val errorMessage: String) : SignUpNavigation()
    data object Success : SignUpNavigation()
}
