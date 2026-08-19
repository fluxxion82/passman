package ai.passman.screens.ui.pgp.crypt

import ai.passman.design.crypt.CryptoToolContent
import ai.passman.design.crypt.model.ToolSet
import ai.passman.design.pgp.longToHex
import ai.passman.screens.ui.password.rememberSavedPasswordPicker
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.viewmodel.pgp.crypt.PgpCryptViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalFocusManager
import androidx.navigation.NavController
import kotlinx.coroutines.launch

@Composable
fun PgpToolsScreen(navController: NavController, snackbarHostState: SnackbarHostState, presenter: PgpCryptViewModel) {
    val scope = rememberCoroutineScope()
    val focusManager = LocalFocusManager.current

    val selectedFilePath by presenter.selectedFilePath.collectAsState()
    val keyPassword by presenter.keyPassword.collectAsState()
    val userId by presenter.currentUserId.collectAsState()
    val inputData by presenter.inputText.collectAsState()
    val outputData by presenter.outputText.collectAsState()
    val pgpKey by presenter.pgpKey.collectAsState()
    val action by presenter.action.collectAsState()
    val availableActions by presenter.availableActions.collectAsState()
    val isFileTarget by presenter.isFileTarget.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()
    val isError by presenter.isError.collectAsState()
    val errorMessage by presenter.errorMessage.collectAsState()

    // A picked password arrives through the same setter the keyboard uses, so the view model never
    // learns where it came from and nothing records that this key was opened with that entry.
    val openSavedPasswordPicker = rememberSavedPasswordPicker {
        presenter.onPasswordChanged(it)
        focusManager.clearFocus()
    }

    CryptoToolContent(
        toolSet = ToolSet.PGP,
        action = action,
        availableActions = availableActions,
        keyAlgorithm = KeystoreKeyAlgorithm.RSA, // only for keystores atm
        isFileTarget = isFileTarget,
        keyName = pgpKey?.publicKey?.keyId?.let { longToHex(it).takeLast(8) }.orEmpty(),
        keyAlias = pgpKey?.publicKey?.fileName.orEmpty(),
        keyFingerprint = pgpKey?.publicKey?.fingerprint.orEmpty(),
        userIds = pgpKey?.publicKey?.userIds?.map { it.copy(comment = "").toString() }.orEmpty(),
        password = keyPassword,
        selectedUserId = userId,
        filePath = selectedFilePath,
        inputData = inputData,
        inputSignatureData = "",
        outputData = outputData,
        isLoading = isLoading,
        isError = isError,
        errorMessage = errorMessage,
        useSalt = false,
        saltIv = "",
        regenSalt = {},
        onSaltIvChanged = {},
        onSaltIvChecked = {},
        onActionSelected = presenter::onActionSelected,
        onTargetToggle = presenter::onTargetToggle,
        onUserIdSelected = presenter::onUserIdSelected,
        onFilePathSelected = presenter::onFileSelectedChanged,
        onTextChanged = presenter::onInputTextChanged,
        onInputSignatureChanged = {},
        onPasswordChanged = presenter::onPasswordChanged,
        onUseSavedPassword = openSavedPasswordPicker,
        onExecuteAction = presenter::onActionClick,
        onCopyClicked = {
            scope.launch {
                snackbarHostState.showSnackbar("Output Copied!")
            }
            presenter.onCopyClicked(it)
        },
    )
}
