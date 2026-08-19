package ai.passman.design.pgp

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors

import ai.passman.design.core.Drop
import ai.passman.design.mapper.toPrimaryKeyName
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SelectableDates
import androidx.compose.material3.Text
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.ripple
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.time.Clock

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddPgpKeyContent(
    algorithmItems: List<PgpKeyAlgorithm>,
    currentAlgorithm: PgpKeyAlgorithm,
    lengthItems: List<String>,
    currentLength: String,
    currentExpiryDate: String,
    name: String,
    email: String,
    password: String,
    isExpirationChecked: Boolean,
    isSavePassToListChecked: Boolean,
    isLoading: Boolean,
    onExpirationChecked: (Boolean) -> Unit,
    onNameChanged: (String) -> Unit,
    onEmailChange:(String) -> Unit,
    onPasswordChange:(String) -> Unit,
    onAlgorithmSelected: (PgpKeyAlgorithm) -> Unit,
    onLengthSelected: (String) -> Unit,
    onDateSelected: (Long) -> Unit,
    onReGenPass: () -> Unit,
    onSavePasswordChecked:(Boolean) -> Unit,
    onCreateClick: () -> Unit,
) {
    var showPicker by remember { mutableStateOf(false) }
    var passwordVisibility by remember { mutableStateOf(false) }
    val algorithmList = remember { algorithmItems.map { algo -> algo.toPrimaryKeyName() } }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
            .formKeyboardNavigation(
                onSubmit = { if (!isLoading) { onCreateClick(); true } else false },
            ),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Create new key pair.", style = MaterialTheme.typography.titleLarge)

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            value = name,
            onValueChange = onNameChanged,
            colors = passmanTextFieldColors(),
            label = {
                Text("Name", color = MaterialTheme.colorScheme.onSurface)
            },
            singleLine = true,
        )

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            value = email,
            onValueChange = onEmailChange,
            colors = passmanTextFieldColors(),
            label = {
                Text("Email", color = MaterialTheme.colorScheme.onSurface)
            },
            singleLine = true,
        )

        Drop(
            modifier = Modifier,
            enabled = true,
            label = "Algorithm",
            value = currentAlgorithm.toPrimaryKeyName(),
            items = algorithmList,
            onItemSelected = { index, item ->
                onAlgorithmSelected(algorithmItems[index])
            },
        )

        Drop(
            modifier = Modifier,
            enabled = true,
            label = "Length",
            value = currentLength,
            items = lengthItems,
            onItemSelected = { index, item ->
                onLengthSelected(item)
            },
        )

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Start) {
            Checkbox(
                checked = isExpirationChecked,
                onCheckedChange = { onExpirationChecked(it) }
            )
            Text(
                modifier = Modifier
                    .padding(end = 10.dp),
                text = "Key will expire on: "
            )

            Text(currentExpiryDate, modifier = Modifier.clickable { showPicker = true })

            if (showPicker) {
                val datePickerState = rememberDatePickerState(selectableDates = object : SelectableDates {
                    override fun isSelectableDate(utcTimeMillis: Long): Boolean {
                        return utcTimeMillis >= Clock.System.now().toEpochMilliseconds()
                    }
                })

                val selectedDate = datePickerState.selectedDateMillis

                DatePickerDialog(
                    onDismissRequest = { showPicker = false },
                    confirmButton = {
                        TextButton(
                            onClick = {
                                if (selectedDate != null) {
                                    onDateSelected(selectedDate)
                                }
                                showPicker = false
                            },
                        ) {
                            Text(text = "OK")
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = {
                            showPicker = false
                        }) {
                            Text(text = "Cancel")
                        }
                    }
                ) {
                    DatePicker(
                        state = datePickerState
                    )
                }
            }

            Spacer(modifier = Modifier.weight(1f))
        }

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(0.dp, 10.dp, 0.dp, 0.dp)
                .background(MaterialTheme.colorScheme.surface),
            value = password,
            onValueChange = onPasswordChange,
            colors = passmanTextFieldColors(),
            visualTransformation = if (passwordVisibility) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                Row {
                    RegeneratePasswordButton(onClick = onReGenPass)
                    PasswordVisibilityToggle(
                        visible = passwordVisibility,
                        onToggle = { passwordVisibility = !passwordVisibility },
                        contentDescription = "password visibility",
                    )
                }
            },
            label = {
                Text("Password", color = MaterialTheme.colorScheme.onSurface)
            },
            singleLine = true,
        )

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Start) {
            Checkbox(
                checked = isSavePassToListChecked,
                onCheckedChange = { onSavePasswordChecked(it) }
            )
            Text(
                modifier = Modifier
                    .padding(end = 10.dp),
                text = "Save password to password list."
            )
            Spacer(modifier = Modifier.weight(1f))
        }

        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier
                    .wrapContentSize()
                    .align(Alignment.CenterHorizontally)
            )
        } else {
            // Primary fill + outline edge: the old surface fill was invisible on this
            // surface-painted form screen in light mode.
            PassmanPrimaryButton(
                text = "Create Key",
                onClick = onCreateClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 50.dp, top = 50.dp, end = 50.dp)
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(bounded = false),
                        onClick = {}
                    ),
                shape = RoundedCornerShape(80),
                fontSize = 18.sp,
            )
        }
    }
}
