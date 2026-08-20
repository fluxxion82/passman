package ai.passman.screens.ui.signup

import ai.passman.design.signup.SignUpContent
import ai.passman.screens.ui.Home
import ai.passman.viewmodel.signup.SignUpViewModel
import ai.passman.viewvo.signup.SignUpNavigation
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarDuration
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun SignupScreen(
    navController: NavController,
    presenter: SignUpViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is SignUpNavigation.Success -> {
                    navController.popBackStack()
                    navController.navigate(Home)
                }

                SignUpNavigation.MissingInformation -> snackbarHostState.showSnackbar("Fill in all fields")
                is SignUpNavigation.InvalidCredentials -> snackbarHostState.showSnackbar(
                    message = event.message,
                    duration = SnackbarDuration.Long,
                )
                SignUpNavigation.AccountExists -> snackbarHostState.showSnackbar("Account already exists")
                is SignUpNavigation.SignupError -> snackbarHostState.showSnackbar(
                    message = "Error: ${event.errorMessage}",
                    duration = SnackbarDuration.Long,
                )
            }
        }
    }

    val userName by presenter.username.collectAsState()
    val password by presenter.password.collectAsState()
    val confirmPassword by presenter.confirmPassword.collectAsState()
    val passwordStrength by presenter.passwordStrength.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()
    val biometricOfferable by presenter.biometricOfferable.collectAsState()
    val enrolBiometric by presenter.enrolBiometric.collectAsState()

    SignUpContent(
        userName = userName,
        password = password,
        confirmPassword = confirmPassword,
        passwordStrength = passwordStrength,
        isLoading = isLoading,
        biometricOfferable = biometricOfferable,
        enrolBiometric = enrolBiometric,
        onUsernameChange = presenter::onUsernameChange,
        onPasswordChange = presenter::onPasswordChange,
        onConfirmPasswordChange = presenter::onConfirmPasswordChange,
        onSignup = presenter::onSignupClicked,
        onEnrolBiometricChanged = presenter::onEnrolBiometricChanged,
    )
}
