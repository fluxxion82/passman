package ai.passman.screens.ui.keystore.details

import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.dialog.ConfirmShareDialog
import ai.passman.design.dialog.EnterPassword
import ai.passman.design.keystore.KeyStoreDetailsContent
import ai.passman.screens.ui.KeystoreAddKey
import ai.passman.screens.ui.KeystoreTools
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.viewmodel.keystore.details.KeystoreDetailsViewModel
import ai.passman.viewvo.navigation.AddKeystoreKey
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.KeystoreTools as KeystoreToolsEvent
import ai.passman.viewvo.navigation.UpdateKeystoreError
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun KeystoreDetailsScreen(
    navController: NavController,
    presenter: KeystoreDetailsViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { navState ->
            when (navState) {
                Back -> navController.navigateUp()

                UpdateKeystoreError -> snackbarHostState.showSnackbar("Error updating keystore")

                is AddKeystoreKey -> navController.navigate(
                    KeystoreAddKey(
                        keystorePath = navState.keystorePath,
                        keystoreName = navState.keystoreName,
                    )
                )

                is KeystoreToolsEvent -> navController.navigate(
                    KeystoreTools.create(
                        keystorePath = navState.keystorePath,
                        keystoreName = navState.keystoreName,
                        keyAlias = navState.keyAlias,
                        action = CryptAction.ENCRYPT,
                        isFileTarget = false,
                    )
                )
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val keystoreInfo by presenter.keystoreInfo.collectAsState()
    val keyStoreName by presenter.keyStoreName.collectAsState()
    val keyStorePassword by presenter.keyStorePassword.collectAsState()
    val keyStorePath by presenter.keyStorePath.collectAsState()
    val keyAliasList by presenter.keyAliasList.collectAsState()
    val isError by presenter.isError.collectAsState()
    val pendingShare by presenter.pendingShare.collectAsState()

    // The VM outlives this screen on the nav backstack — drop any un-confirmed share so the
    // confirmation dialog cannot re-present on a later visit.
    DisposableEffect(presenter) {
        onDispose { presenter.onShareDismissed() }
    }

    var showDeleteConfirmation by remember { mutableStateOf(false) }
    var keyToDelete by remember { mutableStateOf<KeystoreKey?>(null) }

    if (keystoreInfo == null && !isError) {
        EnterPassword(
            keystorePath = keyStoreName,
            password = keyStorePassword,
            onPasswordChange = presenter::onPasswordChanged,
            onDismiss = presenter::onDismissPassword,
            onButtonClicked = presenter::onPasswordEntered,
        )
    } else {
        if (showDeleteConfirmation) {
            val keyTarget = keyToDelete
            ConfirmDeleteDialog(
                title = if (keyTarget != null) "Delete key?" else "Delete keystore?",
                message = if (keyTarget != null) {
                    "Delete key \"${keyTarget.keyAlias}\"? This cannot be undone."
                } else {
                    "Delete keystore \"$keyStoreName\"? This cannot be undone."
                },
                onConfirm = {
                    keyTarget?.let { presenter.onDeleteKeyClick(it) }
                        ?: presenter.onDeleteKeystoreClicked()
                    showDeleteConfirmation = false
                    keyToDelete = null
                },
                onDismiss = {
                    keyToDelete = null
                    showDeleteConfirmation = false
                },
            )
        }
        pendingShare?.let { request ->
            ConfirmShareDialog(
                fileName = request.fileName,
                kind = request.kind,
                onConfirm = presenter::onShareConfirmed,
                onDismiss = presenter::onShareDismissed,
            )
        }
        KeyStoreDetailsContent(
            filePath = keyStorePath,
            keyStoreName = keyStoreName,
            keyAliasList = keyAliasList,
            errorLoading = isError,
            onAddKeyClick = presenter::onAddKeyClick,
            onDeleteKeystoreClick = {
                keyToDelete = null
                showDeleteConfirmation = true
            },
            onDeleteKeyClick = {
                keyToDelete = it
                showDeleteConfirmation = true
            },
            onShareKeystoreClick = presenter::onShareKeystoreClick,
            onToolsClicked = presenter::onKeyToolsClick,
        )
    }
}
