package ai.passman.domain.settings.service

import ai.passman.domain.settings.model.ShareFileRequest

interface SettingsService {
    suspend fun goToBluetoothSettings()
    suspend fun copyToClipboard(text: String)
    /**
     * True when the share flow reached the user (chooser opened / save completed or the user
     * cancelled it); false when a precondition failed - missing file, no foreground activity,
     * copy failure - and nothing was offered.
     */
    suspend fun shareFile(request: ShareFileRequest): Boolean
}
