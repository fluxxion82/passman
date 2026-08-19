package ai.passman.design.core

import androidx.compose.runtime.Composable

interface FileHandler {
    fun openFilePicker()
}

@Composable
expect fun getFileHandler(onFilePathSelected: (String) -> Unit): FileHandler
