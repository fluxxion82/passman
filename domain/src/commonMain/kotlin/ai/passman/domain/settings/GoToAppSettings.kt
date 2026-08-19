package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.service.AppSettingsService

class GoToAppSettings(
    private val repository: AppSettingsService
) : Usecase<Unit, Unit> {

    override suspend fun invoke(param: Unit) = repository.goToAppSettings()
}
