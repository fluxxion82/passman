package ai.passman.viewmodel.pgp

import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.pgp.DeletePgpKey
import ai.passman.domain.pgp.GetAllPgpKeys
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.settings.SyncPgpKeys
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewmodel.base.buildDeleteMessage
import ai.passman.viewmodel.sync.SyncTargetPicker
import ai.passman.viewvo.navigation.PgpHomeNavigation
import ai.passman.viewvo.navigation.PgpKeyDetails
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

open class PgpHomeViewModel(
    private val getAllKeys: GetAllPgpKeys,
    private val syncPgpKeys: SyncPgpKeys,
    getSyncTargets: GetSyncTargets,
    updateTrustedDeviceHost: UpdateTrustedDeviceHost,
    private val deletePgpKey: DeletePgpKey,
    private val importDeveloperKey: ImportDeveloperKey,
) : BaseViewModel() {
    val navigation = Channel<PgpHomeNavigation>()
    val userMessages = Channel<String>(Channel.BUFFERED)

    val keys = MutableStateFlow(listOf<PgpKeyPair>())
    val isLoading = MutableStateFlow(true)
    val syncSessionState = MutableStateFlow<SyncSessionState>(SyncSessionState.Idle)
    val syncTargetPicker = SyncTargetPicker(getSyncTargets, updateTrustedDeviceHost)
    val selectedIds = MutableStateFlow<Set<Long>>(emptySet())
    val inSelectionMode: StateFlow<Boolean> = selectedIds
        .map { it.isNotEmpty() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)
    private var syncJob: Job? = null

    init {
        viewModelScope.launch {
            getAllKeys().collect { keyList ->
                keys.emit(keyList)
                isLoading.emit(false)
            }
        }
    }

    fun onKeyClicked(key: PgpKeyPair) {
        if (inSelectionMode.value) {
            toggleSelect(key)
        } else {
            viewModelScope.launch {
                navigation.send(PgpKeyDetails(key.publicKey.keyId))
            }
        }
    }

    fun onKeyLongPress(key: PgpKeyPair) {
        toggleSelect(key)
    }

    fun toggleSelect(key: PgpKeyPair) {
        val id = key.publicKey.keyId
        val current = selectedIds.value
        selectedIds.value = if (id in current) current - id else current + id
    }

    fun exitSelection() {
        selectedIds.value = emptySet()
    }

    fun deleteSelected() {
        val ids = selectedIds.value
        if (ids.isEmpty()) return
        viewModelScope.launch {
            var success = 0
            var failed = 0
            ids.forEach { id ->
                val outcome = runCatching { deletePgpKey(id) }.getOrNull()
                if (outcome != null && outcome.isSuccessful()) success++ else failed++
            }
            selectedIds.value = emptySet()
            userMessages.send(buildDeleteMessage(success, failed, ids.size, "PGP key"))
        }
    }

    /**
     * The explicit "Import developer key" menu action: re-imports unconditionally (Force), so a
     * user who deleted the key — auto-import never resurrects it — can still get it back.
     */
    fun onImportDeveloperKey() {
        viewModelScope.launch {
            val outcome = runCatching { importDeveloperKey(ImportDeveloperKey.Mode.Force) }.getOrNull()
            userMessages.send(
                if (outcome != null && outcome.isSuccessful()) {
                    "Developer key imported"
                } else {
                    "Failed to import developer key"
                },
            )
        }
    }

    fun onSyncClick() {
        val state = syncSessionState.value
        val visiblyActive = state is SyncSessionState.AwaitingPeer || state is SyncSessionState.Syncing
        if (visiblyActive) {
            syncJob?.cancel()
            syncJob = null
            syncSessionState.value = SyncSessionState.Idle
            return
        }
        // Cancel any lingering hold-open job from a previous session before starting a new one.
        syncJob?.cancel()
        syncJob = null
        viewModelScope.launch {
            syncTargetPicker.requestSync { startSession(it.lastHost) }
        }
    }

    fun onSyncTargetChosen(device: TrustedDevice) {
        syncJob?.cancel()
        syncTargetPicker.dismiss()
        startSession(device.lastHost)
    }

    fun onSyncTargetHostEdited(device: TrustedDevice, host: String) {
        viewModelScope.launch { syncTargetPicker.editHost(device.name, host) }
    }

    /** Error-snackbar action: reopen the chooser so a dead address can be fixed or swapped. */
    fun onChooseDeviceRequest() {
        viewModelScope.launch { syncTargetPicker.open() }
    }

    fun acknowledgeSyncState() {
        syncSessionState.value = SyncSessionState.Idle
    }

    private fun startSession(host: String) {
        syncJob = viewModelScope.launch {
            syncPgpKeys(host).collect { syncSessionState.value = it }
        }
    }
}
