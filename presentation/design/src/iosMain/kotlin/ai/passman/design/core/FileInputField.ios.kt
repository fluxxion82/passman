package ai.passman.design.core

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
actual fun FileInputField(
    modifier: Modifier,
    filePath: String,
    onFilePathSelected: (String) -> Unit,
) {
    val fileHandler = getFileHandler(onFilePathSelected)

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier.fillMaxWidth()
    ) {
        TextField(
            value = filePath,
            onValueChange = { onFilePathSelected(it) },
            label = { Text("File Path", color = MaterialTheme.colorScheme.onSurface) },
            singleLine = true,
            modifier = Modifier.weight(1f)
        )

        Spacer(modifier = Modifier.width(8.dp))

        PassmanPrimaryButton(
            text = "Browse",
            onClick = fileHandler::openFilePicker,
        )
    }
}
