package ai.passman.screens.ui.pgp.userid.add

import ai.passman.design.pgp.AddUserIdContent
import ai.passman.viewvo.navigation.Back
import ai.passman.viewmodel.pgp.userid.add.AddUserIdViewModel
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun AddUserIdScreen(navController: NavController, presenter: AddUserIdViewModel) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
            }
        }
    }

    val pgpKey by presenter.pgpKey.collectAsState()
    val name by presenter.nameState.collectAsState()
    val email by presenter.emailState.collectAsState()
    val password by presenter.passwordState.collectAsState()

    pgpKey?.let {
        AddUserIdContent(
            pgpKey = it.publicKey,
            name = name,
            email = email,
            password = password,
            onNameChange = presenter::onNameChange,
            onEmailChange = presenter::onEmailChange,
            onPasswordChange = presenter::onPasswordChange,
            onCreateClick = presenter::onCreateClick,
        )
    }
}
