package ai.passman.design.settings

import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog

@Composable
fun ReconcileContent(
    onMerge: () -> Unit,
    onOverwrite: () -> Unit,
    onDelete: () -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    errorMessage: String = "",
) {
    Dialog(
        onDismissRequest = { onDismiss() }
    ) {
        Column(
            modifier = modifier
                .background(MaterialTheme.colorScheme.surface)
                .padding(10.dp),
        ) {
            Text(
                modifier = Modifier.padding(8.dp),
                text = "A conflict was detected. The password database received has a conflict with an existing user account. Choose the following option to reconcile the conflict.",
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Start,
                overflow = TextOverflow.Ellipsis,
            )

            if (errorMessage.isNotEmpty()) {
                Text(
                    modifier = Modifier.padding(8.dp),
                    text = errorMessage,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Start,
                )
            }

            // Three parallel choices, so all three take the standard primary button: the old
            // raw primary fill had no edge against the white dialog surface (2.12:1).
            PassmanPrimaryButton(
                text = "Merge",
                onClick = onMerge,
                modifier = Modifier.fillMaxWidth(),
            )

            PassmanPrimaryButton(
                text = "Overwrite",
                onClick = onOverwrite,
                modifier = Modifier.fillMaxWidth(),
            )

            PassmanPrimaryButton(
                // not sure if we need more info if set as Delete (which file are we deleting)
                // Skip makes things easier i guess...can still delete received file
                text = "Skip",
                onClick = onDelete,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
