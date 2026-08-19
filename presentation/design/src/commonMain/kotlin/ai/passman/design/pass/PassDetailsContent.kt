package ai.passman.design.pass

import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors

import ai.passman.design.core.button.ActionButton
import ai.passman.design.core.utils.colorizeString
import ai.passman.design.passmanColors
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.EntryActivity
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.TextField
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.coerceIn
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PassDetailsContent(
    modifier: Modifier = Modifier,
    editMode: Boolean,
    fieldOneLabel: String,
    fieldOneValue: String,
    fieldTwoLabel: String,
    fieldTwoValue: String,
    fieldThreeLabel: String,
    fieldThreeValue: String,
    fieldFourLabel: String,
    fieldFourValue: String,
    fieldFiveLabel: String,
    fieldFiveValue: String,
    buttonLabel: String,
    totpSeed: String,
    totpCode: GenerateTotpCode.TotpCode?,
    customFields: List<CustomField>,
    createdAt: Long,
    lastEditedAt: Long,
    activity: List<EntryActivity>,
    isSaving: Boolean,
    onFieldOneChanged: (String) -> Unit,
    onFieldTwoChanged: (String) -> Unit,
    onFieldThreeChanged: (String) -> Unit,
    onFieldFourChanged: (String) -> Unit,
    onFieldFiveChanged: (String) -> Unit,
    onTotpSeedChanged: (String) -> Unit,
    onScanQrFromImage: () -> Unit,
    onScanQrWithCamera: (() -> Unit)?,
    onTotpCopyClicked: () -> Unit,
    onCustomFieldLabelChanged: (Int, String) -> Unit,
    onCustomFieldValueChanged: (Int, String) -> Unit,
    onCustomFieldSecretToggled: (Int) -> Unit,
    onRemoveCustomField: (Int) -> Unit,
    onAddCustomField: () -> Unit,
    onCustomFieldCopyClicked: (Int) -> Unit,
    onReGenPass: () -> Unit,
    onSaveClicked: () -> Unit,
    onUsernameCopyClicked: () -> Unit,
    onPasswordCopyClicked: () -> Unit,
    onEditClicked: () -> Unit,
    onDeleteClicked: () -> Unit,
) {
    val digitColor = MaterialTheme.colorScheme.primary
    val letterColor = MaterialTheme.colorScheme.onSurface
    val symbolColor = MaterialTheme.passmanColors.warning
    Column(
        modifier = modifier
            // Without ime padding the soft keyboard covers the lower fields and the save button.
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(20.dp)
            // Enter only saves while editing; in view mode the gate declines and the key
            // propagates untouched.
            .formKeyboardNavigation(
                onSubmit = { if (editMode) { onSaveClicked(); true } else false },
            )
    ) {
        Row(
            horizontalArrangement = Arrangement.End,
            modifier = Modifier
                .fillMaxWidth()
        ) {
            IconButton(onClick = {
                onEditClicked()
            }) {
                Icon(imageVector = Icons.Filled.Edit, "edit password")
            }

            IconButton(onClick = onDeleteClicked) {
                Icon(imageVector = Icons.Filled.Delete, "delete password")
            }
        }

        if (fieldOneValue.isNotEmpty()) {
            TextField(
                modifier = Modifier
                    .height(IntrinsicSize.Min)
                    .fillMaxSize()
                    .padding(0.dp, 20.dp, 0.dp, 5.dp),
                value = fieldOneValue,
                onValueChange = {
                    if (editMode) {
                        onFieldOneChanged(it)
                    }
                },
                colors = passmanTextFieldColors(),
                singleLine = true,
                label = {
                    Text(
                        text = fieldOneLabel,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            )
        }

        if (fieldTwoValue.isNotEmpty()) {
            TextField(
                enabled = editMode, // i guess this is needed to get the tap gesture for long click
                modifier = Modifier
                    .height(IntrinsicSize.Min)
                    .fillMaxSize()
                    .padding(0.dp, 5.dp, 0.dp, 5.dp)
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onLongPress = {
                                onUsernameCopyClicked()
                            }
                        )
                    }
                ,
                value = fieldTwoValue,
                onValueChange = {
                    if (editMode) {
                        onFieldTwoChanged(it)
                    }
                },
                colors = passmanTextFieldColors(),
                singleLine = true,
                label = {
                    Text(
                        text = fieldTwoLabel,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            )

        }

        if (fieldThreeValue.isNotEmpty()) {
            val annotatedInitialText = remember(fieldThreeValue, digitColor, letterColor, symbolColor) {
                colorizeString(fieldThreeValue, digitColor, letterColor, symbolColor)
            }
            val fieldThreeTextState = remember { mutableStateOf(TextFieldValue(annotatedInitialText)) }
            LaunchedEffect(fieldThreeValue, digitColor, letterColor, symbolColor) {
                val currentSelection = fieldThreeTextState.value.selection.coerceIn(0, fieldThreeValue.length)
                fieldThreeTextState.value = TextFieldValue(
                    colorizeString(fieldThreeValue, digitColor, letterColor, symbolColor),
                    selection = currentSelection,
                )
            }

            TextField(
                enabled = editMode, // i guess this is needed to get the tap gesture for long click
                modifier = Modifier
                    .height(IntrinsicSize.Min)
                    .fillMaxWidth()
                    .padding(0.dp, 5.dp, 0.dp, 5.dp)
                    .pointerInput(Unit) {
                        detectTapGestures(
                            onLongPress = {
                                onPasswordCopyClicked()
                            }
                        )
                    },
                value = fieldThreeTextState.value,
                onValueChange = {
                    if (editMode) {
                        fieldThreeTextState.value = it
                        onFieldThreeChanged(it.text)
                    }
                },
                colors = passmanTextFieldColors(),
//            visualTransformation = if (passwordVisibility) {
//                VisualTransformation.None
//            } else {
//                PasswordVisualTransformation()
//            },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                trailingIcon = {
                    if (editMode) {
                        RegeneratePasswordButton(onClick = onReGenPass)
                    }
                },
                label = { Text(fieldThreeLabel, color = MaterialTheme.colorScheme.onSurface) },
                singleLine = true,
            )
        }

        if (fieldFourLabel.isNotEmpty()) {
            TextField(
                modifier = Modifier
                    .height(IntrinsicSize.Min)
                    .fillMaxWidth()
                    .padding(0.dp, 5.dp, 0.dp, 5.dp),
                value = fieldFourValue,
                onValueChange = {
                    if (editMode) {
                        onFieldFourChanged(it)
                    }
                },
                colors = passmanTextFieldColors(),
                singleLine = true,
                label = {
                    Text(
                        text = fieldFourLabel,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            )
        }

        if (fieldFiveLabel.isNotEmpty()) {
            TextField(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(IntrinsicSize.Min)
                    .height(140.dp)
                    .padding(0.dp, 5.dp, 0.dp, 5.dp),
                value = fieldFiveValue,
                onValueChange = {
                    if (editMode) {
                        onFieldFiveChanged(it)
                    }
                },
                colors = passmanTextFieldColors(),
                label = {
                    Text(
                        text = fieldFiveLabel,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            )
        }

        if (editMode) {
            TotpSeedField(
                value = totpSeed,
                onChanged = onTotpSeedChanged,
                onScanImageClicked = onScanQrFromImage,
                onScanCameraClicked = onScanQrWithCamera,
            )
        } else {
            totpCode?.let {
                TotpCodeDisplay(
                    totpCode = it,
                    onCopyClicked = onTotpCopyClicked,
                )
            }
        }

        CustomFieldsSection(
            fields = customFields,
            editMode = editMode,
            onLabelChanged = onCustomFieldLabelChanged,
            onValueChanged = onCustomFieldValueChanged,
            onSecretToggled = onCustomFieldSecretToggled,
            onRemoveClicked = onRemoveCustomField,
            onAddClicked = onAddCustomField,
            onCopyClicked = onCustomFieldCopyClicked,
        )

        // Read-only regardless of editMode: history is never a field, so it is not gated behind
        // the edit toggle the way the form above it is.
        EntryHistorySection(
            createdAt = createdAt,
            lastEditedAt = lastEditedAt,
            activity = activity,
        )

        if (editMode) {
            if (isSaving) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .padding(top = 50.dp, bottom = 10.dp),
                )
            } else {
                ActionButton(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(35.dp, 50.dp, 35.dp, 10.dp),
                    RoundedCornerShape(80),
                    // Primary fill (with the outline edge ActionButton adds): a surface fill is
                    // invisible on this surface-painted form screen in light mode.
                    MaterialTheme.colorScheme.primary,
                    buttonLabel,
                    18
                ) {
                    onSaveClicked()
                }
            }
        }
    }
}
