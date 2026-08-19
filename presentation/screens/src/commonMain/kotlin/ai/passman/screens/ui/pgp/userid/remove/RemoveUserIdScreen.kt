package ai.passman.screens.ui.pgp.userid.remove

import ai.passman.design.pgp.RemoveUserIdContent
import ai.passman.viewvo.navigation.Back
import ai.passman.viewmodel.pgp.userid.remove.RemoveUserIdViewModel
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun RemoveUserIdScreen(navController: NavController, presenter: RemoveUserIdViewModel) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
            }
        }
    }

    val pgpKey by presenter.pgpKey.collectAsState()
    val password by presenter.passwordState.collectAsState()

    pgpKey?.let {
        RemoveUserIdContent(
            pgpKey = it.publicKey,
            userId = presenter.userId,
            password = password,
            action = presenter.userIdAction,
            onPasswordChange = presenter::onPasswordChange,
            onRemoveUser = presenter::onRemoveClick,
        )
    }
}
