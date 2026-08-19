package ai.passman.screens.ui.pgp.keys

import ai.passman.design.pgp.ModifyPgpSubkeyContent
import ai.passman.viewvo.navigation.Back
import ai.passman.viewmodel.pgp.keys.ModifyPgpSubkeyViewModel
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun ModifySubKeyScreen(navController: NavController, presenter: ModifyPgpSubkeyViewModel) {
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
        ModifyPgpSubkeyContent(
            pgpKey = it.publicKey,
            subKeyId = presenter.subkeyId,
            password = password,
            subKeyAction = presenter.action,
            onPasswordChange = presenter::onPasswordChange,
            onActionClicked = presenter::onActionClick,
        )
    }
}
