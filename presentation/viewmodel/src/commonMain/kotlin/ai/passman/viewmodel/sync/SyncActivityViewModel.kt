package ai.passman.viewmodel.sync

import ai.passman.domain.base.invoke
import ai.passman.domain.settings.ClearSyncLog
import ai.passman.domain.settings.GetSyncLog
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the Sync Activity screen off Settings: this device's own record of what it synced, with
 * which device, and how it ended (`GetSyncLog`), plus the one destructive action the screen offers
 * — clearing that record (`ClearSyncLog`), gated behind an explicit confirmation because it is the
 * user's own transparency feature and not something a stray tap should be able to erase.
 *
 * The log is loaded once, on entry, the same way [GetSyncLog] is a one-shot suspend call rather
 * than an observed [kotlinx.coroutines.flow.Flow] — syncs are driven from other screens
 * (password/PGP/keystore home), not from this one, so there is nothing for this screen to keep
 * live against while it is open.
 */
class SyncActivityViewModel(
    private val getSyncLog: GetSyncLog,
    private val clearSyncLog: ClearSyncLog,
) : BaseViewModel() {

    val entries = MutableStateFlow<List<SyncLogEntry>>(emptyList())

    /** Drives the "clear log?" confirmation dialog. Nothing is cleared until it is confirmed. */
    val clearConfirmationVisible = MutableStateFlow(false)

    init {
        viewModelScope.launch { entries.value = getSyncLog() }
    }

    fun onClearLogClicked() {
        clearConfirmationVisible.value = true
    }

    fun onClearConfirmationDismissed() {
        clearConfirmationVisible.value = false
    }

    fun onClearConfirmed() {
        viewModelScope.launch {
            clearSyncLog()
            entries.value = emptyList()
            clearConfirmationVisible.value = false
        }
    }
}
