package ai.passman.screens.ui.keystore.crypt

import ai.passman.design.crypt.CryptoToolContent
import ai.passman.design.crypt.model.ToolSet
import ai.passman.screens.ui.password.rememberSavedPasswordPicker
import ai.passman.viewmodel.keystore.crypt.KeystoreCryptViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalFocusManager
import androidx.navigation.NavController
import kotlinx.coroutines.launch

@Composable
fun KeystoreCryptScreen(navController: NavController, snackbarHostState: SnackbarHostState, presenter: KeystoreCryptViewModel) {
    val scope = rememberCoroutineScope()
    val focusManager = LocalFocusManager.current

    val keyAlgorithm by presenter.keystoreKeyAlgorithm.collectAsState()
    val aliasPassword by presenter.aliasPassword.collectAsState()
    val selectedFilePath by presenter.selectedFilePath.collectAsState()
    val inputText by presenter.inputText.collectAsState()
    val inputSignatureData by presenter.inputSignatureData.collectAsState()
    val salt by presenter.saltIv.collectAsState()
    val useSalt by presenter.useSalt.collectAsState()
    val outputData by presenter.outputData.collectAsState()
    val action by presenter.action.collectAsState()
    val availableActions by presenter.availableActions.collectAsState()
    val isFileTarget by presenter.isFileTarget.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()
    val isError by presenter.isError.collectAsState()
    val errorMessage by presenter.errorMessage.collectAsState()

    // A picked password arrives through the same setter the keyboard uses, so the view model never
    // learns where it came from and nothing records that this alias was opened with that entry.
    val openSavedPasswordPicker = rememberSavedPasswordPicker {
        presenter.onPasswordChanged(it)
        focusManager.clearFocus()
    }

    CryptoToolContent(
        toolSet = ToolSet.KEYSTORE,
        action = action,
        availableActions = availableActions,
        keyAlgorithm = keyAlgorithm,
        isFileTarget = isFileTarget,
        keyName = presenter.keystoreName,
        keyAlias = presenter.keyAlias,
        userIds = listOf(),
        password = aliasPassword,
        selectedUserId = "",
        filePath = selectedFilePath,
        saltIv = salt,
        useSalt = useSalt,
        inputData = inputText,
        inputSignatureData = inputSignatureData,
        outputData = outputData,
        isLoading = isLoading,
        isError = isError,
        errorMessage = errorMessage,
        regenSalt = presenter::regenSalt,
        onUserIdSelected = {},
        onFilePathSelected = presenter::onFileSelectedChanged,
        onTextChanged = presenter::onInputTextChanged,
        onInputSignatureChanged = presenter::onInputSignatureChanged,
        onPasswordChanged = presenter::onPasswordChanged,
        onUseSavedPassword = openSavedPasswordPicker,
        onSaltIvChanged = presenter::onSaltIvChanged,
        onSaltIvChecked = presenter::onSaltIvChecked,
        onActionSelected = presenter::onActionSelected,
        onTargetToggle = presenter::onTargetToggle,
        onExecuteAction = presenter::onActionClick,
        onCopyClicked = {
            scope.launch {
                snackbarHostState.showSnackbar("Output Copied!")
            }
            presenter.onCopyClicked(it)
        },
    )
}
