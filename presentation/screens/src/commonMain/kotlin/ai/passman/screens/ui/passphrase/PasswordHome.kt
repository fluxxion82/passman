package ai.passman.screens.ui.passphrase

import ai.passman.design.core.ContextualActionBar
import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.dialog.NoSyncTargetsDialog
import ai.passman.design.dialog.SyncTargetDialog
import ai.passman.design.pass.PassMgmtContent
import ai.passman.screens.ui.PassEntryDetails
import ai.passman.screens.ui.TrustedDevicesRoute
import ai.passman.screens.ui.sync.SyncBanner
import ai.passman.screens.ui.sync.SyncIconAction
import ai.passman.screens.ui.sync.SyncSessionSnackbarEffect
import ai.passman.viewvo.navigation.PassDetails
import ai.passman.viewmodel.passphrase.PasswordHomeViewModel
import ai.passman.viewmodel.sync.SyncTargetPickerState
import ai.passman.viewmodel.sync.lastSyncedLabel
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import kotlin.time.Clock
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun PasswordHome(
    navController: NavController,
    presenter: PasswordHomeViewModel,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is PassDetails -> navController.navigate(PassEntryDetails(event.passUuid))
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val entryList by presenter.entryList.collectAsState()
    val searchVisible by presenter.searchVisible.collectAsState()
    val searchQuery by presenter.searchQuery.collectAsState()
    val syncState by presenter.syncSessionState.collectAsState()
    val syncTargetPicker by presenter.syncTargetPicker.state.collectAsState()
    val selectedIds by presenter.selectedIds.collectAsState()
    val inSelectionMode by presenter.inSelectionMode.collectAsState()
    var showDeleteConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(searchVisible, syncState, inSelectionMode) {
        topBarActions.value = if (inSelectionMode) {
            {}
        } else {
            {
                SyncIconAction(
                    syncState = syncState,
                    contentDescription = "Sync passwords",
                    onClick = { presenter.onSyncClick() },
                )
                IconButton(onClick = { presenter.onSearchToggle() }) {
                    Icon(
                        imageVector = if (searchVisible) Icons.Default.Close else Icons.Default.Search,
                        contentDescription = if (searchVisible) "Close search" else "Search",
                        tint = MaterialTheme.colorScheme.onPrimary,
                    )
                }
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
        successMessage = "Passwords synced",
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
        val selectedName = entryList.firstOrNull { it.uuid in selectedIds }?.entryName
        ConfirmDeleteDialog(
            title = if (count == 1) "Delete password?" else "Delete $count passwords?",
            message = if (count == 1 && selectedName != null) {
                "Delete \"$selectedName\"? This cannot be undone."
            } else {
                "Delete $count passwords? This cannot be undone."
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
        PassMgmtContent(
            passphrases = entryList,
            searchVisible = searchVisible,
            searchQuery = searchQuery,
            selectedIds = selectedIds,
            onSearchQueryChanged = presenter::onSearchQueryChanged,
            onEntryClick = presenter::onEntryClick,
            onEntryLongPress = presenter::onEntryLongPress,
        )
    }
}
