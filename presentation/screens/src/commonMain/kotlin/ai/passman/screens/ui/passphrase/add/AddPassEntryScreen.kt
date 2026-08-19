package ai.passman.screens.ui.passphrase.add

import ai.passman.design.core.getFileHandler
import ai.passman.design.pass.AddEntryContent
import ai.passman.design.pass.QrCameraScannerDialog
import ai.passman.design.pass.cameraQrScanningSupported
import ai.passman.viewmodel.passphrase.add.AddPassEntryViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.InvalidEntry
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun AddPassEntryScreen(
    navController: NavController,
    presenter: AddPassEntryViewModel,
    snackbarHostState: SnackbarHostState,
) {
    // The view model owns the exit: PasswordEvent.Created sends Back once the entry actually
    // saved, and a rejected save (bad TOTP seed) keeps the screen open with the reason.
    // Keyed on the presenter so the collector follows it if the instance is ever swapped.
    LaunchedEffect(presenter) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                Back -> navController.navigateUp()
                is InvalidEntry -> snackbarHostState.showSnackbar(
                    message = event.message,
                    duration = SnackbarDuration.Long,
                )
            }
        }
    }

    val entryName by presenter.entryName.collectAsState()
    val userName by presenter.userName.collectAsState()
    val password by presenter.password.collectAsState()
    val website by presenter.website.collectAsState()
    val notes by presenter.notes.collectAsState()
    val totpSeed by presenter.totpSeed.collectAsState()
    val customFields by presenter.customFields.collectAsState()
    val isSaving by presenter.isSaving.collectAsState()

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

    AddEntryContent(
        fieldOneLabel = "Name",
        fieldOneValue = entryName,
        fieldTwoLabel = "Username",
        fieldTwoValue = userName,
        fieldThreeLabel = "Password",
        fieldThreeValue = password,
        fieldFourLabel = "Website",
        fieldFourValue = website,
        fieldFiveLabel = "Notes",
        fieldFiveValue = notes,
        buttonLabel = "Add",
        totpSeed = totpSeed,
        customFields = customFields,
        isSaving = isSaving,
        onReGenPass = presenter::onReGenPass,
        onFieldOneChanged = presenter::onEntryNameChanged,
        onFieldTwoChanged = presenter::onUserNameChanged,
        onFieldThreeChanged = presenter::onPasswordChanged,
        onFieldFourChanged = presenter::onWebsiteChanged,
        onFieldFiveChanged = presenter::onNotesChanged,
        onTotpSeedChanged = presenter::onTotpSeedChanged,
        onScanQrFromImage = qrImagePicker::openFilePicker,
        onScanQrWithCamera = if (cameraQrScanningSupported) {
            { showScanner = true }
        } else {
            null
        },
        onCustomFieldLabelChanged = presenter::onCustomFieldLabelChanged,
        onCustomFieldValueChanged = presenter::onCustomFieldValueChanged,
        onCustomFieldSecretToggled = presenter::onCustomFieldSecretToggled,
        onRemoveCustomField = presenter::onRemoveCustomField,
        onAddCustomField = presenter::onAddCustomField,
        onSaveClick = presenter::onSaveClick,
    )
}
