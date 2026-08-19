package ai.passman.viewmodel.sync

import ai.passman.domain.base.invoke
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import kotlinx.coroutines.flow.MutableStateFlow

sealed class SyncTargetPickerState {
    data object Hidden : SyncTargetPickerState()

    /** No pairings exist; the only useful action is going to the trusted-devices screen. */
    data object NoDevices : SyncTargetPickerState()

    data class Choosing(val targets: List<TrustedDevice>) : SyncTargetPickerState()
}

/**
 * Shared sync-target selection for the three sync surfaces (passwords, PGP keys, keystores).
 * Owns only the picker; the session itself stays with the owning ViewModel via [requestSync]'s
 * callback.
 *
 * Not thread-safe: call only from a single-threaded/main dispatcher scope — the [inFlight]
 * guard relies on it.
 */
class SyncTargetPicker(
    private val getSyncTargets: GetSyncTargets,
    private val updateTrustedDeviceHost: UpdateTrustedDeviceHost,
) {
    val state = MutableStateFlow<SyncTargetPickerState>(SyncTargetPickerState.Hidden)

    private var inFlight = false

    /** Sync-button entry: one device syncs straight away, anything else needs the user. */
    suspend fun requestSync(startSession: (TrustedDevice) -> Unit) {
        // A second click while the target fetch is still suspended would start a second session.
        if (inFlight) return
        inFlight = true
        try {
            val targets = getSyncTargets()
            when {
                targets.isEmpty() -> state.value = SyncTargetPickerState.NoDevices
                targets.size == 1 -> {
                    state.value = SyncTargetPickerState.Hidden
                    startSession(targets.single())
                }
                else -> state.value = SyncTargetPickerState.Choosing(targets)
            }
        } finally {
            inFlight = false
        }
    }

    /** Recovery entry (error snackbar): always show the list so a dead address can be edited. */
    suspend fun open() {
        val targets = getSyncTargets()
        state.value = if (targets.isEmpty()) {
            SyncTargetPickerState.NoDevices
        } else {
            SyncTargetPickerState.Choosing(targets)
        }
    }

    suspend fun editHost(name: String, host: String) {
        updateTrustedDeviceHost(UpdateTrustedDeviceHost.Parameters(name = name, host = host))
        // Fetch before the guard: a dismiss landing during the fetch must not be overwritten
        // by a stale decision to keep the chooser open.
        val fresh = getSyncTargets()
        if (state.value is SyncTargetPickerState.Choosing) {
            state.value = SyncTargetPickerState.Choosing(fresh)
        }
    }

    fun dismiss() {
        state.value = SyncTargetPickerState.Hidden
    }
}
