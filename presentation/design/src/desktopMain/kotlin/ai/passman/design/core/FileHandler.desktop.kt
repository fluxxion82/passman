package ai.passman.design.core

import ai.passman.logging.KLogger
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import java.io.File
import javax.swing.JFileChooser
import javax.swing.filechooser.FileSystemView

class DesktopFileHandler(val onFilePathSelected: (String) -> Unit) : FileHandler {
    override fun openFilePicker() {
        KLogger.d { "file picker opening" }
        val file = chooseFile()
        if (file == null) {
            KLogger.d { "file picker closed without a selection" }
            return
        }
        KLogger.d { "file picked: ${file.absolutePath}" }
        onFilePathSelected(file.absolutePath)
    }

    private fun chooseFile(): File? {
        val fileChooser = JFileChooser(FileSystemView.getFileSystemView().homeDirectory)
        val result = fileChooser.showOpenDialog(null)
        return if (result == JFileChooser.APPROVE_OPTION) {
            fileChooser.selectedFile
        } else {
            null
        }
    }
}

@Composable
actual fun getFileHandler(onFilePathSelected: (String) -> Unit): FileHandler {
    // The remembered handler must read the CURRENT callback: freezing the first composition's
    // lambda pins whatever view model instance the screen had back then, and a later pick would
    // feed an instance nothing is displaying.
    val latest = rememberUpdatedState(onFilePathSelected)
    return remember { DesktopFileHandler { path -> latest.value.invoke(path) } }
}
