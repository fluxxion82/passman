package ai.passman.screens.ui.keystore.create

import ai.passman.design.keystore.AddKeystoreKeyContent
import ai.passman.viewmodel.keystore.create.AddKeystoreKeyViewModel
import ai.passman.viewvo.navigation.ErrorCreation
import ai.passman.viewvo.navigation.SuccessCreation
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun AddKeystoreKeyScreen(navController: NavController, snackbarHostState: SnackbarHostState, presenter: AddKeystoreKeyViewModel) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { navEvent ->
            when (navEvent) {
                is ErrorCreation -> snackbarHostState.showSnackbar("Error adding key: ${navEvent.message}")
                SuccessCreation -> navController.navigateUp()
            }
        }
    }

    val keyStoreType by presenter.keyStoreType.collectAsState()
    val keyStoreName by presenter.keyStoreName.collectAsState()
    val keyAlias by presenter.keyAlias.collectAsState()
    val keyPassword by presenter.keyPassword.collectAsState()
    val keyAlgorithm by presenter.keyAlgorithm.collectAsState()
    val keystorePassword by presenter.keystorePassword.collectAsState()
    val isSavePassToListChecked by presenter.isSavePassToListChecked.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()

    AddKeystoreKeyContent(
        keyStoreType = keyStoreType,
        keyStoreName = keyStoreName,
        keyAlias = keyAlias,
        keyAlgorithm = keyAlgorithm,
        keyPassword = keyPassword,
        isSavePassToListChecked = isSavePassToListChecked,
        isLoading = isLoading,
        keyStorePassword = keystorePassword,
        onKeyAlgorithmPicked = presenter::onKeyAlgorithmPicked,
        onKeyPasswordChanged = presenter::onKeyPasswordChanged,
        onKeyAliasChanged = presenter::onKeyAliasChanged,
        onKeyStorePasswordChange = presenter::onKeystorePasswordChanged,
        onReGenPass = presenter::onReGenPass,
        onSavePasswordChecked = presenter::onSavePasswordClicked,
        onAddClicked = presenter::onAddKeyClick,
    )
}
