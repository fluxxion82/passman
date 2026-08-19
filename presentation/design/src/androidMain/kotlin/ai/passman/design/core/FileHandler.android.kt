package ai.passman.design.core

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import java.io.File

class AndroidFileHandler(
    private val launcher: ActivityResultLauncher<Intent>,
) : FileHandler {
    override fun openFilePicker() {
        val intent = Intent(Intent.ACTION_GET_CONTENT)
        intent.type = "*/*"
        launcher.launch(intent)
    }
}

@Composable
actual fun getFileHandler(onFilePathSelected: (String) -> Unit): FileHandler {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            uri?.let {
                getFileFromUri(context, it, onFilePathSelected)
            }
        }
    }
    val handler = remember { AndroidFileHandler(launcher) }
    return handler
}

fun getFileFromUri(context: Context, uri: Uri, onFilePathSelected: (String) -> Unit,) {
    var filePath = ""
    val cursor = context.contentResolver.query(uri, null, null, null, null)
    cursor?.use {
        if (it.moveToFirst()) {
            val columnIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val fileName = it.getString(columnIndex)
            val tempFile = File(context.cacheDir, fileName)
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                tempFile.outputStream().use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
            filePath = tempFile.absolutePath
        }
    }
    onFilePathSelected(filePath)
}
