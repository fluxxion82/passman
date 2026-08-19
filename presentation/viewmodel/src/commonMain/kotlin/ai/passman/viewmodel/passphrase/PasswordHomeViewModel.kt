package ai.passman.viewmodel.passphrase

import ai.passman.domain.base.invoke
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.password.DeletePasswords
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.settings.SyncPasswords
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewmodel.base.buildDeleteMessage
import ai.passman.viewmodel.sync.SyncTargetPicker
import ai.passman.viewvo.navigation.PassDetails
import ai.passman.viewvo.navigation.PasswordHomeNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class PasswordHomeViewModel(
    private val getPasswordEntries: GetPasswordEntries,
    private val syncPasswords: SyncPasswords,
    getSyncTargets: GetSyncTargets,
    updateTrustedDeviceHost: UpdateTrustedDeviceHost,
    private val deletePasswords: DeletePasswords,
) : BaseViewModel() {
    val navigation = Channel<PasswordHomeNavigation>(Channel.RENDEZVOUS)
    val userMessages = Channel<String>(Channel.BUFFERED)

    private val allEntries = MutableStateFlow<List<PasswordEntry>>(emptyList())
    val searchVisible = MutableStateFlow(false)
    val searchQuery = MutableStateFlow("")
    /** Entry uuids. The display ordinal is reassigned on every read and cannot hold a selection. */
    val selectedIds = MutableStateFlow<Set<String>>(emptySet())
    val inSelectionMode: StateFlow<Boolean> = selectedIds
        .map { it.isNotEmpty() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    val entryList: StateFlow<List<PasswordEntry>> =
        combine(allEntries, searchQuery) { all, query ->
            if (query.isBlank()) all
            else all.filter { entry ->
                // Deliberately not the stored password: matching on it would leak secrets
                // into a field that autocompletes and stays visible on screen.
                listOf(entry.entryName, entry.username, entry.website, entry.notes)
                    .any { it.contains(query, ignoreCase = true) }
            }
        }.stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    val syncSessionState = MutableStateFlow<SyncSessionState>(SyncSessionState.Idle)
    val syncTargetPicker = SyncTargetPicker(getSyncTargets, updateTrustedDeviceHost)
    private var syncJob: Job? = null

    init {
        viewModelScope.launch {
            getPasswordEntries().collect { passEntryList ->
                allEntries.emit(passEntryList)
            }
        }
    }

    fun onSearchToggle() {
        viewModelScope.launch {
            val newVisible = !searchVisible.value
            searchVisible.emit(newVisible)
            if (!newVisible) searchQuery.emit("")
        }
    }

    fun onSearchQueryChanged(query: String) {
        viewModelScope.launch { searchQuery.emit(query) }
    }

    fun onEntryClick(passUuid: String) {
        if (inSelectionMode.value) {
            toggleSelect(passUuid)
        } else {
            viewModelScope.launch {
                navigation.send(PassDetails(passUuid))
            }
        }
    }

    fun onEntryLongPress(passUuid: String) {
        toggleSelect(passUuid)
    }

    fun toggleSelect(passUuid: String) {
        val current = selectedIds.value
        selectedIds.value = if (passUuid in current) current - passUuid else current + passUuid
    }

    fun exitSelection() {
        selectedIds.value = emptySet()
    }

    fun deleteSelected() {
        val ids = selectedIds.value
        if (ids.isEmpty()) return
        viewModelScope.launch {
            val total = ids.size
            // Clamped to the selection the confirmation dialog counted. `deletePasswordEntries`
            // removes at most one row per uuid, so this holds by construction — but the toast and the
            // dialog have to agree about how many passwords the user just deleted, and that agreement
            // should not depend on a repository invariant a future change could quietly drop.
            val deleted = runCatching { deletePasswords(ids) }.getOrDefault(0).coerceIn(0, total)
            val failed = total - deleted
            selectedIds.value = emptySet()
            userMessages.send(buildDeleteMessage(deleted, failed, total, "password"))
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
        syncTargetPicker.dismiss()
        viewModelScope.launch {
            // Wait for the previous session's job to actually finish, not just be marked
            // cancelled, before starting the new one. The transfer server lease is refcounted
            // now, so this can't leave a sibling session serverless either way — but a restart
            // that outran its predecessor's own stopTransferServer() lease release was one of the
            // original causes of the intermittent sync failures this fixes, and a join here costs
            // nothing.
            syncJob?.cancelAndJoin()
            startSession(device.lastHost)
        }
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
            syncPasswords(host).collect { syncSessionState.value = it }
        }
    }
}
