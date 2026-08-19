package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.service.SettingsService

class CopyToClipboard(
    private val repository: SettingsService
) : Usecase<String, Unit> {

    override suspend fun invoke(param: String) = repository.copyToClipboard(param)
}
