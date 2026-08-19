package ai.passman.screens.ui.passphrase.details

import ai.passman.design.core.getFileHandler
import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.pass.PassDetailsContent
import ai.passman.design.pass.QrCameraScannerDialog
import ai.passman.design.pass.cameraQrScanningSupported
import ai.passman.viewmodel.passphrase.details.PassDetailsViewModel
import ai.passman.viewvo.passphrase.Back
import ai.passman.viewvo.passphrase.Copied
import ai.passman.viewvo.passphrase.ShowMessage
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

@Composable
fun PassDetailsScreen(
    navController: NavController,
    presenter: PassDetailsViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()

                Copied -> launch {
                    snackbarHostState.showSnackbar("Copied!")
                }

                is ShowMessage -> launch {
                    snackbarHostState.showSnackbar(event.message)
                }
            }
        }
    }

    val entryName by presenter.entryName.collectAsState()
    val userName by presenter.userName.collectAsState()
    val password by presenter.password.collectAsState()
    val website by presenter.website.collectAsState()
    val notes by presenter.notes.collectAsState()
    val totpSeed by presenter.totpSeed.collectAsState()
    val totpCode by presenter.totpCode.collectAsState()
    val customFields by presenter.customFields.collectAsState()
    val createdAt by presenter.createdAt.collectAsState()
    val lastEditedAt by presenter.lastEditedAt.collectAsState()
    val activity by presenter.activity.collectAsState()
    val editModeEnabled by presenter.editMode.collectAsState()
    val isSaving by presenter.isSaving.collectAsState()

    var showDeleteConfirm by remember { mutableStateOf(false) }
    var showScanner by remember { mutableStateOf(false) }
    val qrImagePicker = getFileHandler { path -> presenter.onQrImagePicked(path) }

    if (showScanner) {
        QrCameraScannerDialog(
            onResult = { payload ->
                presenter.onQrScanned(payload)
                showScanner = false
            },
            onDismiss = { showScanner = false },
        )
    }

    if (showDeleteConfirm) {
        ConfirmDeleteDialog(
            title = "Delete password?",
            message = if (entryName.isNotBlank()) {
                "Delete \"$entryName\"? This cannot be undone."
            } else {
                "Delete this password? This cannot be undone."
            },
            onConfirm = {
                showDeleteConfirm = false
                presenter.onDeleteClicked()
            },
            onDismiss = { showDeleteConfirm = false },
        )
    }

    PassDetailsContent(
        editMode = editModeEnabled,
        fieldOneLabel = "name",
        fieldOneValue = entryName,
        fieldTwoLabel = "username",
        fieldTwoValue = userName,
        fieldThreeLabel = "password",
        fieldThreeValue = password,
        fieldFourLabel = "website",
        fieldFourValue = website,
        fieldFiveLabel = "notes",
        fieldFiveValue = notes,
        buttonLabel = "Save",
        totpSeed = totpSeed,
        totpCode = totpCode,
        customFields = customFields,
        createdAt = createdAt,
        lastEditedAt = lastEditedAt,
        activity = activity,
        isSaving = isSaving,
        onTotpSeedChanged = presenter::onTotpSeedChanged,
        onScanQrFromImage = qrImagePicker::openFilePicker,
        onScanQrWithCamera = if (cameraQrScanningSupported) {
            { showScanner = true }
        } else {
            null
        },
        onTotpCopyClicked = presenter::onTotpCopyClicked,
        onCustomFieldLabelChanged = presenter::onCustomFieldLabelChanged,
        onCustomFieldValueChanged = presenter::onCustomFieldValueChanged,
        onCustomFieldSecretToggled = presenter::onCustomFieldSecretToggled,
        onRemoveCustomField = presenter::onRemoveCustomField,
        onAddCustomField = presenter::onAddCustomField,
        onCustomFieldCopyClicked = presenter::onCustomFieldCopyClicked,
        onReGenPass = presenter::onReGenPass,
        onFieldOneChanged = presenter::onEntryNameChanged,
        onFieldTwoChanged = presenter::onUserNameChanged,
        onFieldThreeChanged = presenter::onPasswordChanged,
        onFieldFourChanged = presenter::onWebsiteChanged,
        onFieldFiveChanged = presenter::onNotesChanged,
        onSaveClicked = presenter::onSaveClick,
        onUsernameCopyClicked = presenter::onUsernameCopyClicked,
        onPasswordCopyClicked = presenter::onPasswordCopyClicked,
        onEditClicked = presenter::onEditClicked,
        onDeleteClicked = { showDeleteConfirm = true },
    )
}
