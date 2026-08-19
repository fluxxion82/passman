package ai.passman.design.core

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
expect fun FileInputField(
    modifier: Modifier = Modifier,
    filePath: String,
    onFilePathSelected: (String) -> Unit,
)
