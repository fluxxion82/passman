package ai.passman.screens.ui.pgp.keys

import ai.passman.design.pgp.AddPgpKeyContent
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.ErrorMessage
import ai.passman.viewmodel.pgp.keys.PgpAddKeyViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun AddPgpKeyScreen(navController: NavController, snackbarHostState: SnackbarHostState, presenter: PgpAddKeyViewModel) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
                is ErrorMessage -> {
                    snackbarHostState.showSnackbar(event.message)
                    navController.navigateUp()
                }
            }
        }
    }

    val currentAlgorithm by presenter.currentAlgorithm.collectAsState()
    val currentLength by presenter.lengthState.collectAsState()
    val lengthOptions by presenter.lengthOptions.collectAsState()
    val name by presenter.nameState.collectAsState()
    val email by presenter.emailState.collectAsState()
    val date by presenter.dateState.collectAsState()
    val password by presenter.password.collectAsState()
    val expirationChecked by presenter.isExpirationChecked.collectAsState()
    val isSavePassToListChecked by presenter.isSavePassToListChecked.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()

    AddPgpKeyContent(
        algorithmItems = PgpKeyAlgorithm.entries.minus(PgpKeyAlgorithm.RSA_SIGN),
        currentAlgorithm = currentAlgorithm,
        lengthItems = lengthOptions,
        currentLength = currentLength,
        currentExpiryDate = date,
        name = name,
        email = email,
        password = password,
        isExpirationChecked = expirationChecked,
        isSavePassToListChecked = isSavePassToListChecked,
        isLoading = isLoading,
        onNameChanged = presenter::onNameChange,
        onEmailChange = presenter::onEmailChange,
        onExpirationChecked = presenter::onExpirationEnabled,
        onDateSelected = presenter::onDateSelected,
        onAlgorithmSelected = presenter::onAlgorithmSelected,
        onLengthSelected = presenter::onLengthSelected,
        onPasswordChange = presenter::onPasswordChanged,
        onReGenPass = presenter::onReGenPass,
        onSavePasswordChecked = presenter::onSavePasswordClicked,
        onCreateClick = presenter::onCreateSubkeyClick,
    )
}
