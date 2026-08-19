package ai.passman.domain.settings.repository

import ai.passman.domain.settings.model.ClipboardExpiry

/**
 * Stores the clipboard-expiry preference. Holds no secret of its own — only how long one of the
 * user's secrets may sit on the system clipboard, and whether the expiry runs at all.
 */
interface ClipboardPreferences {
    suspend fun getExpiry(): ClipboardExpiry
    suspend fun setExpiry(expiry: ClipboardExpiry)
}
