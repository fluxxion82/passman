package ai.passman.android.platform.service

import ai.passman.domain.settings.service.AppSettingsService
import android.content.Intent
import android.net.Uri
import android.provider.Settings

internal class AndroidAppSettingsService(
    private val activityProvider: ActivityProvider
) : AppSettingsService {

    override suspend fun goToAppSettings() {
        activityProvider.get()?.run {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).setData(
                    Uri.fromParts("package", packageName, null)
                )
            )
        }
    }
}
