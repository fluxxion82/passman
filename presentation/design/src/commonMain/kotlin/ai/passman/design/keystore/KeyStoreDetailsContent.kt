package ai.passman.design.keystore

import ai.passman.design.core.button.LabeledTonalIconButton
import ai.passman.domain.keystore.model.KeystoreKey
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Share
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val keystoreKeyHeaders = listOf("Key Alias", "Algorithm")
@Composable
fun KeyStoreDetailsContent(
    filePath: String,
    keyStoreName: String,
    keyAliasList: List<KeystoreKey>,
    errorLoading: Boolean,
    onAddKeyClick: () -> Unit,
    onToolsClicked: (KeystoreKey) -> Unit,
    onDeleteKeystoreClick: () -> Unit,
    onDeleteKeyClick: (KeystoreKey) -> Unit,
    onShareKeystoreClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val selectedRow = remember { mutableStateOf(-1) }  // -1 means no selection

    Column(modifier = modifier.padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 5.dp),
        ) {
            Column {
                Text(
                    modifier = Modifier.padding(start = 16.dp, top = 15.dp, bottom = 5.dp),
                    text = keyStoreName,
                    fontWeight = FontWeight.Bold,
                    fontSize = 20.sp,
                )
                Text(
                    modifier = Modifier.padding(start = 16.dp),
                    text = filePath,
                )
            }
        }

        Column(
            modifier = Modifier.padding(16.dp),
        ) {
            Row {
                keystoreKeyHeaders.forEach { title ->
                    Text(
                        text = title,
                        modifier = Modifier
                            .weight(1f)
                            .padding(4.dp),
                        maxLines = 1,
                    )
                }
            }

            HorizontalDivider()

            if (errorLoading) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Error,
                        contentDescription = "error",
                        tint = MaterialTheme.colorScheme.error,
                    )
                    Text(
                        text = "Error Loading keystore"
                    )
                }
            } else {
                LazyColumn {
                    items(keyAliasList) { key ->
                        val index = keyAliasList.indexOf(key)
                        val isSelected = selectedRow.value == index
                        Row(
                            modifier = Modifier
                                .clickable { selectedRow.value = if (isSelected) -1 else index }
                                .background(
                                    if (isSelected) MaterialTheme.colorScheme.secondary.copy(alpha = 0.3f) else Color.Transparent,
                                )
                        ) {
                            Text(
                                text = key.keyAlias,
                                modifier = Modifier.weight(1f).padding(8.dp),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                text = "${key.keyAlgorithm}",
                                modifier = Modifier.weight(1f).padding(8.dp),
                                style = MaterialTheme.typography.titleSmall,
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.weight(1f))

                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceEvenly,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    KeystoreDetailsActionRow(
                        keySelected = selectedRow.value > -1,
                        showDelete = !keyAliasList.any { it.keyAlias.equals("passmanMain") },
                        onAddKeyClick = onAddKeyClick,
                        onToolsClicked = {
                            onToolsClicked(keyAliasList[selectedRow.value])
                        },
                        onDeleteKeyClick = {
                            onDeleteKeyClick(keyAliasList[selectedRow.value])
                            selectedRow.value = -1
                        },
                        onDeleteKeystoreClick = onDeleteKeystoreClick,
                        onShareKeystoreClick = onShareKeystoreClick,
                    )
                }
            }
        }
    }
}

@Composable
fun KeystoreDetailsActionRow(
    keySelected: Boolean,
    showDelete: Boolean,
    onAddKeyClick: () -> Unit,
    onToolsClicked: () -> Unit,
    onDeleteKeystoreClick: () -> Unit,
    onDeleteKeyClick: () -> Unit,
    onShareKeystoreClick: () -> Unit,
) {
    if (keySelected) {
        LabeledTonalIconButton(
            icon = Icons.Filled.Build,
            label = "Tools",
            onClick = onToolsClicked,
        )
        if (showDelete) {
            LabeledTonalIconButton(
                icon = Icons.Filled.Delete,
                label = "Delete",
                onClick = onDeleteKeyClick,
            )
        }
    } else {
        LabeledTonalIconButton(
            icon = Icons.Filled.Add,
            label = "Add",
            onClick = onAddKeyClick,
        )
        if (showDelete) {
            LabeledTonalIconButton(
                icon = Icons.Filled.Delete,
                label = "Delete",
                onClick = onDeleteKeystoreClick,
            )
        }
        LabeledTonalIconButton(
            icon = Icons.Filled.Share,
            label = "Share keystore file",
            onClick = onShareKeystoreClick,
            // Wider than the 72dp default and two label lines: the label states what the Share
            // actually emits and must survive larger font scales without clipping.
            modifier = Modifier.width(128.dp),
            labelMaxLines = 2,
        )
    }
}
