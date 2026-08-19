package ai.passman.screens.ui.splash

import ai.passman.design.splash.DuelOptionContent
import ai.passman.screens.ui.Login
import ai.passman.screens.ui.Signup
import ai.passman.viewmodel.splash.SplashViewModel
import ai.passman.viewvo.splash.SplashNavigation
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
actual fun SplashScreen(
    navController: NavController,
    presenter: SplashViewModel,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { navState ->
            when (navState) {
                SplashNavigation.Login -> navController.navigate(Login)

                SplashNavigation.SignUp -> navController.navigate(Signup)
            }
        }
    }

    DuelOptionContent(
        title = "PassMan",
        optionOneText = "Login",
        optionTwoText = "Sign Up",
        onOptionOneClicked = presenter::onLoginClicked,
        onOptionTwoClicked = presenter::onSignUpClicked,
    )
}
