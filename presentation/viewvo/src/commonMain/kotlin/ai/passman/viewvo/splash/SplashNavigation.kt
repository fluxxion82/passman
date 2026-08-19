package ai.passman.viewvo.splash

sealed class SplashNavigation {
    data object Login : SplashNavigation()
    data object SignUp : SplashNavigation()
}
