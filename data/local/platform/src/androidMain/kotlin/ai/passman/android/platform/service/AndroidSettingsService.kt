package ai.passman.android.platform.service

import ai.passman.platform.service.ExpiringClipboard
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.logging.KLogger
import ai.passman.domain.settings.service.SettingsService
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File

internal class AndroidSettingsService(
    private val activityProvider: ActivityProvider,
    private val context: Context,
    private val clipboard: ExpiringClipboard,
) : SettingsService {

    override suspend fun goToBluetoothSettings() {
        activityProvider.get()?.run {
            startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
        }
    }

    /**
     * Expiry, the sensitive-content flag and the rule about only clearing our own clip all live in
     * [ExpiringClipboard] and [AndroidSystemClipboard].
     */
    override suspend fun copyToClipboard(text: String) {
        clipboard.copy(text)
    }

    override suspend fun shareFile(request: ShareFileRequest): Boolean {
        val file = File(request.filePath)
        if (!file.isFile) {
            KLogger.e { "shareFile: not a file: ${request.filePath}" }
            return false
        }
        val fileUri: Uri = runCatching {
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        }.getOrElse {
            KLogger.e(it) { "shareFile: path is outside the FileProvider root" }
            return false
        }
        val shareIntent: Intent = Intent().apply {
            action = Intent.ACTION_SEND
            putExtra(Intent.EXTRA_STREAM, fileUri)
            // The Sharesheet preview headline on API 29+; createChooser's title argument is
            // ignored there but still feeds older/OEM sheets.
            putExtra(Intent.EXTRA_TITLE, request.shareTitle)
            type = "*/*"
            // ClipData + the read flag grants the URI only to the component the user actually
            // picks. Never pre-grant via grantUriPermission to every share-capable app: those
            // grants outlive the share and are never revoked.
            clipData = ClipData.newRawUri("", fileUri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val activity = activityProvider.get() ?: run {
            KLogger.e { "shareFile: no foreground activity to launch the chooser" }
            return false
        }
        activity.startActivity(Intent.createChooser(shareIntent, request.shareTitle))
        return true
    }
}
