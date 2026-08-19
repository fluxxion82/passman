package ai.passman.platform.prefs.impl

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.settings.repository.ThemePreferences
import com.russhwolf.settings.Settings
import kotlinx.coroutines.withContext

class LocalThemePreferences(
    encryptedFactory: EncryptionSettingsFactory,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : ThemePreferences {
    private val settings: Settings = encryptedFactory.createEncrypted(PREFS_NAME)

    override suspend fun getMode(): ThemeMode = withContext(coroutinesContextFacade.io) {
        ThemeMode.entries.firstOrNull { it.name == settings.getStringOrNull(MODE) } ?: ThemeMode.System
    }

    override suspend fun setMode(mode: ThemeMode) = withContext(coroutinesContextFacade.io) {
        settings.putString(MODE, mode.name)
    }

    private companion object {
        const val PREFS_NAME = "theme_prefs"
        const val MODE = "theme_mode"
    }
}
