package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.repository.ClipboardPreferences
import com.russhwolf.settings.Settings
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.withContext

/**
 * The clipboard-expiry setting, stored as a flag plus a duration in milliseconds.
 *
 * Keeping the duration in the store — rather than compiling it in and persisting only the toggle —
 * is what lets the value be tuned later without a second format change. It shares the same
 * encrypted store the other preferences use; nothing secret is kept here, that is simply the one
 * settings path this module has on all three platforms.
 */
class LocalClipboardPreferences(
    encryptedFactory: EncryptionSettingsFactory,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : ClipboardPreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)

    override suspend fun getExpiry(): ClipboardExpiry = withContext(coroutinesContextFacade.io) {
        ClipboardExpiry(
            enabled = settings.getBooleanOrNull(ENABLED) ?: ClipboardExpiry.Default.enabled,
            // A missing, unparseable or non-positive stored value falls back to the default rather
            // than to "clear immediately", which would take the clip away before it can be pasted.
            duration = settings.getLongOrNull(DURATION_MILLIS)
                ?.takeIf { it > 0 }
                ?.milliseconds
                ?: ClipboardExpiry.Default.duration,
        )
    }

    override suspend fun setExpiry(expiry: ClipboardExpiry) = withContext(coroutinesContextFacade.io) {
        settings.putBoolean(ENABLED, expiry.enabled)
        settings.putLong(DURATION_MILLIS, expiry.duration.inWholeMilliseconds)
    }

    private companion object {
        const val PREFS_NAME = "clipboard_prefs"
        const val ENABLED = "expiry_enabled"
        const val DURATION_MILLIS = "expiry_millis"
    }
}
