package ai.passman.screens.ui.keystore

import ai.passman.design.core.ContextualActionBar
import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.dialog.NoSyncTargetsDialog
import ai.passman.design.dialog.SyncTargetDialog
import ai.passman.design.keystore.KeystoreHomeContent
import ai.passman.screens.ui.CreateKeystore
import ai.passman.screens.ui.KeystoreDetails
import ai.passman.screens.ui.TrustedDevicesRoute
import ai.passman.screens.ui.sync.SyncBanner
import ai.passman.screens.ui.sync.SyncIconAction
import ai.passman.screens.ui.sync.SyncSessionSnackbarEffect
import ai.passman.viewmodel.keystore.KeystoreHomeViewModel
import ai.passman.viewmodel.sync.SyncTargetPickerState
import ai.passman.viewmodel.sync.lastSyncedLabel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.KeystoreDetails as KeystoreDetailsEvent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import kotlin.time.Clock
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun KeystoreHomeScreen(
    navController: NavController,
    presenter: KeystoreHomeViewModel,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is KeystoreDetailsEvent ->
                    navController.navigate(
                        KeystoreDetails(
                            keystorePath = event.keystorePath,
                            keystoreName = event.keystoreName,
                        )
                    )

                Back -> navController.popBackStack()
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val keystores by presenter.keystoreList.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()
    val syncState by presenter.syncSessionState.collectAsState()
    val syncTargetPicker by presenter.syncTargetPicker.state.collectAsState()
    val selectedIds by presenter.selectedIds.collectAsState()
    val inSelectionMode by presenter.inSelectionMode.collectAsState()
    val currentUserName by presenter.currentUserName.collectAsState()
    var showDeleteConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(syncState, inSelectionMode) {
        topBarActions.value = if (inSelectionMode) {
            {}
        } else {
            {
                SyncIconAction(
                    syncState = syncState,
                    contentDescription = "Sync keystores",
                    onClick = { presenter.onSyncClick() },
                )
            }
        }
    }

    LaunchedEffect(inSelectionMode, selectedIds.size) {
        topBarOverride.value = if (inSelectionMode) {
            {
                ContextualActionBar(
                    selectedCount = selectedIds.size,
                    onExit = presenter::exitSelection,
                    onDelete = { showDeleteConfirm = true },
                )
            }
        } else null
    }

    DisposableEffect(Unit) {
        onDispose { topBarOverride.value = null }
    }

    SyncSessionSnackbarEffect(
        syncState = syncState,
        snackbarHostState = snackbarHostState,
        successMessage = "Keystores synced",
        onChooseDevice = presenter::onChooseDeviceRequest,
        onAcknowledge = presenter::acknowledgeSyncState,
    )

    when (val picker = syncTargetPicker) {
        SyncTargetPickerState.Hidden -> Unit
        SyncTargetPickerState.NoDevices -> NoSyncTargetsDialog(
            onGoToTrustedDevices = {
                presenter.syncTargetPicker.dismiss()
                navController.navigate(TrustedDevicesRoute)
            },
            onDismiss = presenter.syncTargetPicker::dismiss,
        )
        is SyncTargetPickerState.Choosing -> SyncTargetDialog(
            targets = picker.targets,
            lastSyncedLabel = { lastSyncedLabel(it.lastSyncedAt, Clock.System.now().toEpochMilliseconds()) },
            onSync = presenter::onSyncTargetChosen,
            onEditHost = presenter::onSyncTargetHostEdited,
            onManageDevices = {
                presenter.syncTargetPicker.dismiss()
                navController.navigate(TrustedDevicesRoute)
            },
            onDismiss = presenter.syncTargetPicker::dismiss,
        )
    }

    if (showDeleteConfirm) {
        val count = selectedIds.size
        val selectedName = keystores.firstOrNull { presenter.keystoreId(it) in selectedIds }?.name
        ConfirmDeleteDialog(
            title = if (count == 1) "Delete keystore?" else "Delete $count keystores?",
            message = if (count == 1 && selectedName != null) {
                "Delete \"$selectedName\"? This cannot be undone."
            } else {
                "Delete $count keystores? This cannot be undone."
            },
            onConfirm = {
                presenter.deleteSelected()
                showDeleteConfirm = false
            },
            onDismiss = { showDeleteConfirm = false },
        )
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        SyncBanner(syncState = syncState, onCancel = { presenter.onSyncClick() })
        KeystoreHomeContent(
            keystores = keystores,
            selectedIds = selectedIds,
            currentUserName = currentUserName,
            keystoreId = presenter::keystoreId,
            onKeystoreClick = presenter::onKeystoreClicked,
            onKeystoreLongPress = presenter::onKeystoreLongPress,
            onCreateKeystore = { navController.navigate(CreateKeystore) },
            isLoading = isLoading,
        )
    }
}
