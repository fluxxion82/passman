package ai.passman.design.core

import androidx.compose.runtime.Composable

@Composable
actual fun getFileHandler(onFilePathSelected: (String) -> Unit): FileHandler =
    object : FileHandler {
        override fun openFilePicker() {
            // iOS file picker not yet implemented (would use UIDocumentPickerViewController via cinterop).
        }
    }
