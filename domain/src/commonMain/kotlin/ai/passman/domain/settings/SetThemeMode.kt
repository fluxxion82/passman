package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.settings.repository.ThemePreferences

class SetThemeMode(
    private val preferences: ThemePreferences,
) : Usecase<ThemeMode, Unit> {

    override suspend fun invoke(param: ThemeMode) = preferences.setMode(param)
}
