package ai.passman.screens.ui.pgp.keys

import ai.passman.design.pgp.DeleteKeyContent
import ai.passman.screens.ui.PgpHome
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.DeleteSuccess
import ai.passman.viewmodel.pgp.keys.DeleteKeyViewModel
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun DeleteKeyScreen(navController: NavController, presenter: DeleteKeyViewModel) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
                DeleteSuccess -> navController.navigate(PgpHome) {
                    popUpTo<PgpHome> {
                        inclusive = true
                    }
                }
            }
        }
    }

    val isError by presenter.isError.collectAsState()
    val errorMessage by presenter.errorMessage.collectAsState()

    DeleteKeyContent(
        isError = isError,
        errorMessage = errorMessage,
        onConfirmDeleteClick = presenter::onConfirmDeleteClick,
        onCancelClick = presenter::onCancelClick,
    )
}
