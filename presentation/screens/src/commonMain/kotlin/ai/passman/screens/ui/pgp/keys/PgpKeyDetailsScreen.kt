package ai.passman.screens.ui.pgp.keys

import ai.passman.design.dialog.ConfirmShareDialog
import ai.passman.design.dialog.ExportPassphraseDialog
import ai.passman.design.pgp.PgpKeyDisplay
import ai.passman.screens.ui.PgpAddSubKey
import ai.passman.screens.ui.PgpAddUserId
import ai.passman.screens.ui.PgpChangePassword
import ai.passman.screens.ui.PgpConfirmDelete
import ai.passman.screens.ui.PgpModifySubKey
import ai.passman.screens.ui.PgpRemoveUserId
import ai.passman.screens.ui.PgpTools
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.settings.model.ShareFileKind
import ai.passman.viewvo.navigation.*
import ai.passman.viewmodel.pgp.keys.PgpKeyDetailsViewModel
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun PgpKeyDetailsScreen(
    navController: NavController,
    presenter: PgpKeyDetailsViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is PgpToolAction -> navController.navigate(
                    PgpTools.create(
                        keyId = event.keyId.toString(),
                        action = CryptAction.ENCRYPT,
                        isFileTarget = false,
                    )
                )
                is AddUserId -> navController.navigate(PgpAddUserId(event.keyId.toString()))
                is RemoveUserId -> navController.navigate(PgpRemoveUserId.create(event.keyId.toString(), event.userId, event.action))
                is RevokeUserId -> navController.navigate(PgpRemoveUserId.create(event.keyId.toString(), event.userId, event.action))
                // Expiry editing is not implemented and no UI currently emits these events;
                // a no-op beats TODO()'s NotImplementedError if they are ever wired up early.
                is ChangeExpiryKey, is ChangeExpirySubKey -> Unit
                is ChangePassword -> navController.navigate(PgpChangePassword(event.keyId.toString()))
                is AddSubKey -> navController.navigate(PgpAddSubKey(event.keyId.toString()))
                is ModifySubKey -> navController.navigate(PgpModifySubKey.create(event.keyId.toString(), event.subkeyId, event.action))
                is KeyDeleted -> navController.navigate(PgpConfirmDelete(event.keyId.toString()))
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val key by presenter.pgpKey.collectAsState()
    val pendingShare by presenter.pendingShare.collectAsState()
    val exportPassphraseRequested by presenter.exportPassphraseRequested.collectAsState()

    // The VM outlives this screen on the nav backstack: without this, a confirmed-passphrase
    // export dialog could re-present on return and a single tap would ship the secret ring.
    DisposableEffect(presenter) {
        onDispose {
            presenter.onShareDismissed()
            presenter.onExportPassphraseDismissed()
        }
    }

    if (exportPassphraseRequested) {
        ExportPassphraseDialog(
            keyName = presenter.keyDisplayName(),
            onConfirm = presenter::onExportPassphraseEntered,
            onDismiss = presenter::onExportPassphraseDismissed,
        )
    }

    pendingShare?.let { request ->
        ConfirmShareDialog(
            fileName = request.fileName,
            kind = request.kind,
            onConfirm = presenter::onShareConfirmed,
            onDismiss = presenter::onShareDismissed,
            detail = if (request.kind == ShareFileKind.PrivateKey) {
                key?.publicKey?.fingerprint?.let { "Fingerprint: $it" }
            } else {
                null
            },
        )
    }

    key?.let {
        PgpKeyDisplay(
            pgpKeyPair = it,
            onToolsClicked = presenter::onToolsClicked,
            onAddUserId = presenter::onAddUserId,
            onRemoveUserId = presenter::onRemoveUserId,
            onRevokeUserId = presenter::onRevokeUserId,
            onAddSubKey = presenter::onAddSubKey,
            onRemoveSubKey = presenter::onRemoveSubKey,
            onRevokeSubKey = presenter::onRevokeSubKey,
            onChangeExpirationDate = presenter::onChangeExpirationDate,
            onChangeExpirationDateSub = presenter::onChangeExpirationDateSub,
            onChangePassword = presenter::onChangePassword,
            onShareKeyClick = presenter::onShareKeyClick,
            onExportPrivateKey = presenter::onExportPrivateKeyClick,
            onDeleteKeyClick = presenter::onDeleteKeyClick,
        )
    }
}
