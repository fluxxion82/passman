package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.domain.settings.service.SettingsService

class ShareFile(
    private val settingsService: SettingsService,
): Usecase<ShareFileRequest, Boolean> {
    override suspend fun invoke(param: ShareFileRequest): Boolean =
        settingsService.shareFile(param)
}
