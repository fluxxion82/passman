package ai.passman.screens.ui.login

import ai.passman.design.login.LoginContent
import ai.passman.screens.ui.Home
import ai.passman.screens.ui.Splash
import ai.passman.logging.KLogger
import ai.passman.viewmodel.login.LoginViewModel
import ai.passman.viewvo.login.LoginNavigation
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

@Composable
fun LoginScreen(navController: NavController, presenter: LoginViewModel, snackbarHostState: SnackbarHostState) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { navState ->
            when (navState) {
                is LoginNavigation.GoToHome -> {
                    KLogger.i { "Go to home screen" }
                    navController.navigate(Home) {
                        popUpTo<Splash> {
                            inclusive = true
                        }
                    }
                }

                is LoginNavigation.LoginError -> launch {
                    snackbarHostState.showSnackbar(navState.message)
                }
            }
        }
    }

    val isLoading by presenter.isLoading.collectAsState()
    val knownUsernames by presenter.knownUsernames.collectAsState()

    LoginContent(
        userName = presenter.username,
        password = presenter.password,
        isLoading = isLoading,
        knownUsernames = knownUsernames,
        onUsernameChange = presenter::onUsernameChange,
        onPasswordChange = presenter::onPasswordChange,
        onLogin = presenter::onLogin,
    )
}
