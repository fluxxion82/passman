package ai.passman.viewvo.login

sealed class LoginNavigation {
    data object GoToHome : LoginNavigation()
    data class LoginError(val message: String) : LoginNavigation()
}
