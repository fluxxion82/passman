package ai.passman.viewmodel.sync

sealed class SyncState {
    data object Idle : SyncState()
    data object Syncing : SyncState()
    data object Success : SyncState()
    data class Error(val message: String, val noSavedAddress: Boolean = false) : SyncState()
}
