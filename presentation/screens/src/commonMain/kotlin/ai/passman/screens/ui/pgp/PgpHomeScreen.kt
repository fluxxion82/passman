package ai.passman.screens.ui.pgp

import ai.passman.design.core.ContextualActionBar
import ai.passman.design.core.OverflowMenuAction
import ai.passman.design.core.OverflowMenuItem
import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.dialog.NoSyncTargetsDialog
import ai.passman.design.dialog.SyncTargetDialog
import ai.passman.design.pgp.PgpKeysList
import ai.passman.screens.ui.CreatePgpKey
import ai.passman.screens.ui.PgpKeyDetails
import ai.passman.screens.ui.TrustedDevicesRoute
import ai.passman.screens.ui.sync.SyncBanner
import ai.passman.screens.ui.sync.SyncIconAction
import ai.passman.screens.ui.sync.SyncSessionSnackbarEffect
import ai.passman.viewvo.navigation.PgpKeyDetails as PgpKeyDetailsEvent
import ai.passman.viewmodel.pgp.PgpHomeViewModel
import ai.passman.viewmodel.sync.SyncTargetPickerState
import ai.passman.viewmodel.sync.lastSyncedLabel
import ai.passman.viewmodel.sync.rememberNowMs
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun PgpHomeScreen(
    navController: NavController,
    presenter: PgpHomeViewModel,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
    snackbarHostState: SnackbarHostState,
) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is PgpKeyDetailsEvent -> {
                    navController.navigate(PgpKeyDetails(event.keyId.toString()))
                }
            }
        }
    }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val pgpKeys by presenter.keys.collectAsState()
    val isLoading by presenter.isLoading.collectAsState()
    val syncState by presenter.syncSessionState.collectAsState()
    val syncTargetPicker by presenter.syncTargetPicker.state.collectAsState()
    val selectedIds by presenter.selectedIds.collectAsState()
    val inSelectionMode by presenter.inSelectionMode.collectAsState()
    var showDeleteConfirm by remember { mutableStateOf(false) }

    LaunchedEffect(syncState, inSelectionMode) {
        topBarActions.value = if (inSelectionMode) {
            {}
        } else {
            {
                SyncIconAction(
                    syncState = syncState,
                    contentDescription = "Sync PGP keys",
                    onClick = { presenter.onSyncClick() },
                )
                OverflowMenuAction(
                    items = listOf(
                        OverflowMenuItem("Import developer key", presenter::onImportDeveloperKey),
                    ),
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
        successMessage = "PGP keys synced",
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
        is SyncTargetPickerState.Choosing -> {
            // Hoisted out of the label lambda: a clock read inside the composable body is sampled
            // once per composition, so "Just now" would still say "Just now" on a chooser the user
            // left open for an hour. rememberNowMs re-publishes it while the dialog is up.
            val nowMs = rememberNowMs()
            SyncTargetDialog(
                targets = picker.targets,
                lastSyncedLabel = { lastSyncedLabel(it.lastSyncedAt, nowMs) },
                onSync = presenter::onSyncTargetChosen,
                onEditHost = presenter::onSyncTargetHostEdited,
                onManageDevices = {
                    presenter.syncTargetPicker.dismiss()
                    navController.navigate(TrustedDevicesRoute)
                },
                onDismiss = presenter.syncTargetPicker::dismiss,
            )
        }
    }

    if (showDeleteConfirm) {
        val count = selectedIds.size
        val selectedName = pgpKeys.firstOrNull { it.publicKey.keyId in selectedIds }
            ?.publicKey?.userIds?.firstOrNull()?.name
        ConfirmDeleteDialog(
            title = if (count == 1) "Delete PGP key?" else "Delete $count PGP keys?",
            message = if (count == 1 && selectedName != null) {
                "Delete \"$selectedName\"? This cannot be undone."
            } else {
                "Delete $count PGP keys? This cannot be undone."
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
        PgpKeysList(
            keys = pgpKeys,
            selectedIds = selectedIds,
            onKeyClick = presenter::onKeyClicked,
            onKeyLongPress = presenter::onKeyLongPress,
            onCreateKey = { navController.navigate(CreatePgpKey) },
            isLoading = isLoading,
        )
    }
}
