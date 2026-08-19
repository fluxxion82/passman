package ai.passman.design.pass

import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors

import ai.passman.design.core.button.ActionButton
import ai.passman.design.core.utils.colorizeString
import ai.passman.design.passmanColors
import ai.passman.domain.password.model.CustomField
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.TextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.coerceIn
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun AddEntryContent(
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
    customFields: List<CustomField>,
    isSaving: Boolean,
    onFieldOneChanged: (String) -> Unit,
    onFieldTwoChanged: (String) -> Unit,
    onFieldThreeChanged: (String) -> Unit,
    onFieldFourChanged: (String) -> Unit,
    onFieldFiveChanged: (String) -> Unit,
    onTotpSeedChanged: (String) -> Unit,
    onScanQrFromImage: () -> Unit,
    onScanQrWithCamera: (() -> Unit)?,
    onCustomFieldLabelChanged: (Int, String) -> Unit,
    onCustomFieldValueChanged: (Int, String) -> Unit,
    onCustomFieldSecretToggled: (Int) -> Unit,
    onRemoveCustomField: (Int) -> Unit,
    onAddCustomField: () -> Unit,
    onReGenPass: () -> Unit,
    onSaveClick: () -> Unit,
) {
    val digitColor = MaterialTheme.colorScheme.primary
    val letterColor = MaterialTheme.colorScheme.onSurface
    val symbolColor = MaterialTheme.passmanColors.warning
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

    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(20.dp)
            .formKeyboardNavigation(onSubmit = { onSaveClick(); true })
    ) {
        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .fillMaxSize()
                .padding(0.dp, 5.dp, 0.dp, 5.dp),
            value = fieldOneValue,
            onValueChange = {
                onFieldOneChanged(it)
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

        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .fillMaxSize()
                .padding(0.dp, 5.dp, 0.dp, 5.dp),
            value = fieldTwoValue,
            onValueChange = {
                onFieldTwoChanged(it)
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

        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .fillMaxSize()
                .padding(0.dp, 5.dp, 0.dp, 5.dp)
            ,
            value = fieldThreeTextState.value,
            onValueChange = {
                // sPassword = it
                onFieldThreeChanged(it.text)
                fieldThreeTextState.value = it
            },
            colors = passmanTextFieldColors(),
//            visualTransformation = if (passwordVisibility) {
//                VisualTransformation.None
//            } else {
//                PasswordVisualTransformation()
//            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                RegeneratePasswordButton(onClick = onReGenPass)
            },
            label = { Text(fieldThreeLabel, color = MaterialTheme.colorScheme.onSurface) },
            singleLine = true,
        )

        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .fillMaxSize()
                .padding(0.dp, 5.dp, 0.dp, 5.dp),
            value = fieldFourValue,
            onValueChange = {
                onFieldFourChanged(it)
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

        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .height(140.dp)
                .fillMaxSize()
                .padding(0.dp, 5.dp, 0.dp, 5.dp),
            value = fieldFiveValue,
            onValueChange = {
                onFieldFiveChanged(it)
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

        TotpSeedField(
            value = totpSeed,
            onChanged = onTotpSeedChanged,
            onScanImageClicked = onScanQrFromImage,
            onScanCameraClicked = onScanQrWithCamera,
        )

        CustomFieldsSection(
            fields = customFields,
            editMode = true,
            onLabelChanged = onCustomFieldLabelChanged,
            onValueChanged = onCustomFieldValueChanged,
            onSecretToggled = onCustomFieldSecretToggled,
            onRemoveClicked = onRemoveCustomField,
            onAddClicked = onAddCustomField,
            onCopyClicked = {},
        )

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
                onSaveClick()
            }
        }
    }
}
