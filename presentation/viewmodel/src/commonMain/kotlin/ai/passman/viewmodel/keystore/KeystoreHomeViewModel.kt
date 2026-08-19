package ai.passman.viewmodel.keystore

import ai.passman.domain.base.invoke
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.keystore.DeleteKeystore
import ai.passman.domain.keystore.GetAllKeystores
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.settings.SyncKeystores
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.domain.user.GetAppUser
import ai.passman.domain.user.models.AppUser
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewmodel.base.buildDeleteMessage
import ai.passman.viewmodel.sync.SyncTargetPicker
import ai.passman.viewvo.navigation.KeystoreDetails
import ai.passman.viewvo.navigation.KeystoreNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

open class KeystoreHomeViewModel(
    private val getAllKeystores: GetAllKeystores,
    private val syncKeystores: SyncKeystores,
    getSyncTargets: GetSyncTargets,
    updateTrustedDeviceHost: UpdateTrustedDeviceHost,
    private val deleteKeystore: DeleteKeystore,
    private val getAppUser: GetAppUser,
) : BaseViewModel() {
    val navigation = Channel<KeystoreNavigation>()
    val userMessages = Channel<String>(Channel.BUFFERED)

    val keystoreList = MutableStateFlow<List<KeyStoreInfo>>(emptyList())
    val isLoading = MutableStateFlow(true)
    val syncSessionState = MutableStateFlow<SyncSessionState>(SyncSessionState.Idle)
    val syncTargetPicker = SyncTargetPicker(getSyncTargets, updateTrustedDeviceHost)
    val currentUserName = MutableStateFlow<String?>(null)
    val selectedIds = MutableStateFlow<Set<String>>(emptySet())
    val inSelectionMode: StateFlow<Boolean> = selectedIds
        .map { it.isNotEmpty() }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)
    private var syncJob: Job? = null

    init {
        viewModelScope.launch {
            getAllKeystores().collect {
                keystoreList.emit(it)
                isLoading.emit(false)
            }
        }
        viewModelScope.launch {
            getAppUser().collect { user ->
                currentUserName.value = when (user) {
                    is AppUser.LoggedIn -> user.userName
                    is AppUser.AccountCreated -> user.userName
                    AppUser.Anonymous -> null
                }
            }
        }
    }

    fun keystoreId(keystore: KeyStoreInfo): String = "${keystore.path}::${keystore.name}"

    fun isProtected(keystore: KeyStoreInfo): Boolean {
        val name = currentUserName.value ?: return false
        return keystore.name.equals("$name.pfx", ignoreCase = true)
    }

    fun onKeystoreClicked(keystore: KeyStoreInfo) {
        if (inSelectionMode.value) {
            if (isProtected(keystore)) {
                notifyProtected()
            } else {
                toggleSelect(keystore)
            }
        } else {
            viewModelScope.launch { navigation.send(KeystoreDetails(keystore.path, keystore.name)) }
        }
    }

    fun onKeystoreLongPress(keystore: KeyStoreInfo) {
        if (isProtected(keystore)) {
            notifyProtected()
            return
        }
        toggleSelect(keystore)
    }

    fun toggleSelect(keystore: KeyStoreInfo) {
        if (isProtected(keystore)) return
        val id = keystoreId(keystore)
        val current = selectedIds.value
        selectedIds.value = if (id in current) current - id else current + id
    }

    private fun notifyProtected() {
        viewModelScope.launch {
            userMessages.send("This keystore is required for login and can't be deleted")
        }
    }

    fun exitSelection() {
        selectedIds.value = emptySet()
    }

    fun deleteSelected() {
        val ids = selectedIds.value
        if (ids.isEmpty()) return
        val targets = keystoreList.value.filter { keystoreId(it) in ids && !isProtected(it) }
        viewModelScope.launch {
            var success = 0
            var failed = 0
            targets.forEach { keystore ->
                val ok = runCatching {
                    deleteKeystore(
                        DeleteKeystore.DeleteKeystoreRequest(
                            keystorePath = keystore.path,
                            keystoreName = keystore.name,
                            keystorePassword = "",
                        )
                    )
                }.getOrElse { false }
                if (ok) success++ else failed++
            }
            selectedIds.value = emptySet()
            userMessages.send(buildDeleteMessage(success, failed, targets.size, "keystore"))
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
            syncKeystores(host).collect { syncSessionState.value = it }
        }
    }
}
