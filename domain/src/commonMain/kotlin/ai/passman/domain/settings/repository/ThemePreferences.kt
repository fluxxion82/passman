package ai.passman.domain.settings.repository

import ai.passman.domain.settings.model.ThemeMode

interface ThemePreferences {
    suspend fun getMode(): ThemeMode
    suspend fun setMode(mode: ThemeMode)
}
