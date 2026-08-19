package ai.passman.design.pgp

import ai.passman.design.core.Drop
import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.design.mapper.toItemListName
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.domain.pgp.model.PgpKeyPair
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SelectableDates
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import kotlin.time.Clock

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddSubKeyContent(
    keyPair: PgpKeyPair,
    algorithmItems: List<PgpKeyAlgorithm>,
    currentAlgorithm: PgpKeyAlgorithm,
    lengthItems: List<String>,
    currentLength: String,
    currentExpiryDate: String,
    password: String,
    isExpirationEnabled: Boolean,
    isLoading: Boolean,
    onExpirationChecked: (Boolean) -> Unit,
    onPasswordChange: (String) -> Unit,
    onAlgorithmSelected: (PgpKeyAlgorithm) -> Unit,
    onLengthSelected: (String) -> Unit,
    onDateSelected: (Long) -> Unit,
    onCreateClick: () -> Unit,
) {
    var showPicker by remember { mutableStateOf(false) }
    var passwordVisible by remember { mutableStateOf(false) }
    val algorithmList = remember(algorithmItems) { algorithmItems.map(PgpKeyAlgorithm::toItemListName) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(
                onSubmit = { if (!isLoading) { onCreateClick(); true } else false },
            ),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = "Configure a subkey for ${longToHex(keyPair.publicKey.keyId).takeLast(8)}.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Key options", style = MaterialTheme.typography.labelLarge)
            Drop(
                modifier = Modifier.fillMaxWidth(),
                enabled = true,
                label = "Algorithm",
                value = currentAlgorithm.toItemListName(),
                items = algorithmList,
                onItemSelected = { index, _ -> onAlgorithmSelected(algorithmItems[index]) },
            )
            Drop(
                modifier = Modifier.fillMaxWidth(),
                enabled = true,
                label = "Length",
                value = currentLength,
                items = lengthItems,
                onItemSelected = { _, item -> onLengthSelected(item) },
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = isExpirationEnabled,
                    onCheckedChange = onExpirationChecked,
                )
                Text("Key expires", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.weight(1f))
                Text(
                    text = currentExpiryDate,
                    modifier = Modifier.clickable { showPicker = true },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Password", style = MaterialTheme.typography.labelLarge)
            TextField(
                modifier = Modifier.fillMaxWidth(),
                value = password,
                onValueChange = onPasswordChange,
                colors = passmanTextFieldColors(),
                label = { Text("Password") },
                placeholder = { Text("Enter the key password") },
                visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    PasswordVisibilityToggle(
                        visible = passwordVisible,
                        onToggle = { passwordVisible = !passwordVisible },
                        contentDescription = "Toggle password visibility",
                    )
                },
                singleLine = true,
            )
        }

        PassmanPrimaryButton(
            modifier = Modifier.fillMaxWidth(),
            enabled = !isLoading,
            onClick = onCreateClick,
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(end = 8.dp),
                    // The spinner only shows while the button is disabled, so it sits on the
                    // 12%-alpha disabled fill, not primary: onSurface, not onPrimary.
                    color = MaterialTheme.colorScheme.onSurface,
                    strokeWidth = 2.dp,
                )
            }
            Text("Add subkey", fontWeight = FontWeight.Bold)
        }
    }

    if (showPicker) {
        val datePickerState = rememberDatePickerState(selectableDates = object : SelectableDates {
            override fun isSelectableDate(utcTimeMillis: Long): Boolean =
                utcTimeMillis >= Clock.System.now().toEpochMilliseconds()
        })
        DatePickerDialog(
            onDismissRequest = { showPicker = false },
            confirmButton = {
                TextButton(
                    onClick = {
                        datePickerState.selectedDateMillis?.let(onDateSelected)
                        showPicker = false
                    },
                ) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { showPicker = false }) { Text("Cancel") } },
        ) {
            DatePicker(state = datePickerState)
        }
    }
}
