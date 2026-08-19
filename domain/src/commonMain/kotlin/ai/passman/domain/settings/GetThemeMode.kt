package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.domain.settings.repository.ThemePreferences

class GetThemeMode(
    private val preferences: ThemePreferences,
) : Usecase<Unit, ThemeMode> {

    override suspend fun invoke(param: Unit): ThemeMode = preferences.getMode()
}
