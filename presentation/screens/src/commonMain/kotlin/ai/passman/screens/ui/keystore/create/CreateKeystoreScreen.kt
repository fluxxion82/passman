package ai.passman.screens.ui.keystore.create

import ai.passman.design.keystore.CreateKeyStoreContent
import ai.passman.viewmodel.keystore.create.CreateKeyStoreViewModel
import ai.passman.viewvo.navigation.ErrorCreation
import ai.passman.viewvo.navigation.SuccessCreation
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

@Composable
fun CreateKeyStore(
    navController: NavController,
    presenter: CreateKeyStoreViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { navState ->
            when (navState) {
                SuccessCreation -> navController.popBackStack()

                is ErrorCreation -> launch {
                    snackbarHostState.showSnackbar("Failed to create: ${navState.message}")
                }
            }
        }
    }

    val keyStoreName by presenter.keyStoreName.collectAsState()
    val keystorePassword by presenter.keystorePassword.collectAsState()
    val keyAlias by presenter.keyAlias.collectAsState()
    val keyPassword by presenter.aliasPassword.collectAsState()
    val keyAlgorithm by presenter.keyAlgorithm.collectAsState()
    val saveKeystorePassChecked by presenter.isSaveStorePassToListChecked.collectAsState()
    val saveKeyPassChecked by presenter.isSaveKeyPassToListChecked.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()

    CreateKeyStoreContent(
        keyStoreName = keyStoreName,
        keystorePassword = keystorePassword,
        keyAlias = keyAlias,
        keyPassword = keyPassword,
        keyAliasAlgorithm = keyAlgorithm,
        isSaveStorePassToListChecked = saveKeystorePassChecked,
        isSaveKeyPassToListChecked = saveKeyPassChecked,
        isLoading = isLoading,
        onKeystoreNameChanged = presenter::onKeystoreNameChanged,
        onPasswordChanged = presenter::onKeystorePasswordChanged,
        onKeyAliasChanged = presenter::onKeyAliasChanged,
        onKeyPasswordChanged = presenter::onKeyPasswordChanged,
        onReGenStorePass = presenter::onReGenStorePass,
        onReGenKeyPass = presenter::onReGenKeyPass,
        onSaveStorePasswordChecked = presenter::onSaveStorePasswordClicked,
        onSaveKeyPasswordChecked = presenter::onSaveKeyPasswordClicked,
        onCreate = presenter::onCreate,
        onKeyAlgorithmPicked = presenter::onKeyAlgorithmPicked,
    )
}
