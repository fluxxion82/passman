package ai.passman.screens.ui.pgp.keys

import ai.passman.design.pgp.ChangePasswordContent
import ai.passman.viewvo.navigation.Back
import ai.passman.viewmodel.pgp.keys.ChangePasswordViewModel
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun ChangePasswordScreen(navController: NavController, presenter: ChangePasswordViewModel) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
            }
        }
    }

    val oldPassword = presenter.oldPasswordState.collectAsState().value
    val newPassword = presenter.newPasswordState.collectAsState().value

    ChangePasswordContent(
        oldPassword = oldPassword,
        newPassword = newPassword,
        onOldPasswordChange = presenter::onOldPasswordChange,
        onNewPasswordChange = presenter::onNewPasswordChange,
        onActionClicked = presenter::onActionClick,
    )
}
