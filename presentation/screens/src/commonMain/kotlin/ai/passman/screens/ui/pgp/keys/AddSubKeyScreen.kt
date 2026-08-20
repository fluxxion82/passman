package ai.passman.screens.ui.pgp.keys

import ai.passman.design.pgp.AddSubKeyContent
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.ErrorMessage
import ai.passman.viewmodel.pgp.keys.PgpAddSubKeyViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun AddSubKeyScreen(navController: NavController, snackbarHostState: SnackbarHostState, presenter: PgpAddSubKeyViewModel) {
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

    val key by presenter.pgpKey.collectAsState()
    val currentAlgorithm by presenter.currentAlgorithm.collectAsState()
    val currentLength by presenter.lengthState.collectAsState()
    val lengthOptions by presenter.lengthOptions.collectAsState()
    val date by presenter.dateState.collectAsState()
    val password by presenter.passwordState.collectAsState()
    val expirationChecked by presenter.expirationSet.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()

    key?.let {
        AddSubKeyContent(
            keyPair = it,
            // An allowlist, not a denylist: PgpClient.addSubKey dispatches on an algorithm string
            // and only knows these three. A new entry in PgpKeyAlgorithm used to appear here for
            // free and then fail at the repository, so the list names what actually works.
            algorithmItems = listOf(
                PgpKeyAlgorithm.RSA_SIGN,
                PgpKeyAlgorithm.RSA_ENCRYPT,
                PgpKeyAlgorithm.ELGAMAL_ENCRYPT,
            ),
            currentAlgorithm = currentAlgorithm,
            lengthItems = lengthOptions,
            currentLength = currentLength,
            currentExpiryDate = date,
            password = password,
            isExpirationEnabled = expirationChecked,
            isLoading = isLoading,
            onExpirationChecked = presenter::onExpirationEnabled,
            onDateSelected = presenter::onDateSelected,
            onAlgorithmSelected = presenter::onAlgorithmSelected,
            onLengthSelected = presenter::onLengthSelected,
            onPasswordChange = presenter::onPasswordChanged,
            onCreateClick = presenter::onCreateSubkeyClick,
        )
    }
}
