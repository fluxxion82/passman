package ai.passman.design.crypt

import ai.passman.design.core.DropdownField
import ai.passman.design.core.FileInputField
import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors
import ai.passman.design.crypt.model.ToolSet
import ai.passman.domain.crypto.model.CryptAction
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Badge
import ai.passman.design.core.button.PassmanPrimaryButton
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp

@Composable
fun CryptoToolContent(
    toolSet: ToolSet,
    action: CryptAction,
    availableActions: List<CryptAction> = CryptAction.entries.toList(),
    keyAlgorithm: KeystoreKeyAlgorithm,
    isFileTarget: Boolean,
    keyName: String,
    keyAlias: String,
    keyFingerprint: String = "",
    userIds: List<String>,
    useSalt: Boolean,
    saltIv: String,
    password: String,
    selectedUserId: String,
    filePath: String,
    inputData: String,
    inputSignatureData: String,
    outputData: String,
    isLoading: Boolean,
    isError: Boolean,
    errorMessage: String? = null,
    onActionSelected: (CryptAction) -> Unit = {},
    onTargetToggle: (Boolean) -> Unit = {},
    onUserIdSelected: (String) -> Unit,
    onFilePathSelected: (String) -> Unit,
    onTextChanged: (String) -> Unit,
    onInputSignatureChanged: (String) -> Unit,
    regenSalt: () -> Unit,
    onSaltIvChanged: (String) -> Unit,
    onSaltIvChecked: (Boolean) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onExecuteAction: () -> Unit,
    onCopyClicked: (String) -> Unit,
    modifier: Modifier = Modifier,
    /**
     * Opens the saved-password picker for the password field below. Null on hosts that have no
     * vault to pick from, in which case the affordance is simply absent — typing stays the only
     * way in, exactly as before.
     */
    onUseSavedPassword: (() -> Unit)? = null,
) {
    var passwordVisibility by remember { mutableStateOf(false) }
    val selectedBaseAction = action.baseAction()
    val scrollState = rememberScrollState()

    LaunchedEffect(outputData.isNotEmpty(), errorMessage) {
        if (outputData.isNotEmpty() || errorMessage != null) {
            scrollState.animateScrollTo(scrollState.maxValue)
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(scrollState)
            .padding(16.dp)
            // Enter in the multiline message/signature fields still inserts a newline — those
            // fields consume the key before this post handler; only single-line fields submit.
            .formKeyboardNavigation(
                onSubmit = { if (!isLoading) { onExecuteAction(); true } else false },
            ),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        KeyIdentityHeader(
            toolSet = toolSet,
            keyAlgorithm = keyAlgorithm,
            keyName = keyName,
            keyAlias = keyAlias,
            keyFingerprint = keyFingerprint,
            userIds = userIds,
            selectedUserId = selectedUserId,
            onUserIdSelected = onUserIdSelected,
        )

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                baseCryptActions.forEachIndexed { index, baseAction ->
                    SegmentedButton(
                        selected = selectedBaseAction == baseAction,
                        onClick = { onActionSelected(baseAction) },
                        enabled = baseAction in availableActions,
                        shape = SegmentedButtonDefaults.itemShape(index, baseCryptActions.size),
                        label = { Text(baseAction.label()) },
                    )
                }
            }

            selectedBaseAction.combinedAction()?.let { combinedAction ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = action == combinedAction,
                        onCheckedChange = if (combinedAction in availableActions) {
                            { checked -> onActionSelected(if (checked) combinedAction else selectedBaseAction) }
                        } else {
                            null
                        },
                        enabled = combinedAction in availableActions,
                    )
                    Text(
                        text = when (selectedBaseAction) {
                            CryptAction.ENCRYPT -> "Also sign"
                            CryptAction.DECRYPT -> "Also verify signature"
                            else -> error("Only encrypt and decrypt have combined actions")
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }

            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                targetOptions.forEachIndexed { index, (fileTarget, label) ->
                    SegmentedButton(
                        selected = isFileTarget == fileTarget,
                        onClick = { onTargetToggle(fileTarget) },
                        shape = SegmentedButtonDefaults.itemShape(index, targetOptions.size),
                        label = { Text(label) },
                    )
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = action.inputLabel(), style = MaterialTheme.typography.labelLarge)
            if (isFileTarget) {
                FileInputField(
                    modifier = Modifier.fillMaxWidth(),
                    filePath = filePath,
                    onFilePathSelected = onFilePathSelected,
                )
            } else {
                OutlinedTextField(
                    value = inputData,
                    onValueChange = onTextChanged,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(action.inputLabel()) },
                    placeholder = { Text(action.inputPlaceholder()) },
                    minLines = 4,
                    colors = passmanTextFieldColors(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }

            if (toolSet == ToolSet.KEYSTORE && action.requiresSignature()) {
                Text(text = "Signature", style = MaterialTheme.typography.labelLarge)
                OutlinedTextField(
                    value = inputSignatureData,
                    onValueChange = onInputSignatureChanged,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Signature") },
                    placeholder = { Text("Paste the signature to verify") },
                    minLines = 4,
                    colors = passmanTextFieldColors(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
            }

            if (toolSet == ToolSet.KEYSTORE && keyAlgorithm == KeystoreKeyAlgorithm.AES) {
                SaltRow(
                    useSalt = useSalt,
                    saltIv = saltIv,
                    onSaltIvChecked = onSaltIvChecked,
                    onSaltIvChanged = onSaltIvChanged,
                    regenSalt = regenSalt,
                )
            }

            if (action.requiresPassword()) {
                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChanged,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Passphrase") },
                    singleLine = true,
                    isError = isError,
                    colors = passmanTextFieldColors(),
                    visualTransformation = if (passwordVisibility) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        PasswordVisibilityToggle(
                            visible = passwordVisibility,
                            onToggle = { passwordVisibility = !passwordVisibility },
                            contentDescription = if (passwordVisibility) "Hide passphrase" else "Show passphrase",
                        )
                    },
                )

                // The picker feeds the same setter as typing, so the tool never receives a
                // password source or any association with the vault entry that supplied it.
                onUseSavedPassword?.let { openPicker ->
                    TextButton(onClick = openPicker) {
                        Text("Use saved password")
                    }
                }
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            PassmanPrimaryButton(
                onClick = onExecuteAction,
                modifier = Modifier.fillMaxWidth(),
                enabled = !isLoading,
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        // The spinner only shows while the button is disabled, so it sits on
                        // the 12%-alpha disabled fill, not primary: onSurface, not onPrimary.
                        color = MaterialTheme.colorScheme.onSurface,
                        strokeWidth = 2.dp,
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                }
                Text(action.buttonLabel(), fontWeight = FontWeight.Bold)
            }

            errorMessage?.let { message ->
                Surface(
                    color = MaterialTheme.colorScheme.errorContainer,
                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                    shape = MaterialTheme.shapes.small,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = "Error",
                            tint = MaterialTheme.colorScheme.onErrorContainer,
                        )
                        Text(
                            text = message,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                }
            }
        }

        if (outputData.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    contentColor = MaterialTheme.colorScheme.onSurface,
                ),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(text = "Output", style = MaterialTheme.typography.labelLarge)
                        Spacer(modifier = Modifier.weight(1f))
                        IconButton(onClick = { onCopyClicked(outputData) }) {
                            Icon(
                                imageVector = Icons.Filled.ContentCopy,
                                contentDescription = "Copy output",
                            )
                        }
                    }
                    SelectionContainer {
                        Text(
                            text = outputData,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(max = 320.dp)
                                .verticalScroll(rememberScrollState()),
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun KeyIdentityHeader(
    toolSet: ToolSet,
    keyAlgorithm: KeystoreKeyAlgorithm,
    keyName: String,
    keyAlias: String,
    keyFingerprint: String,
    userIds: List<String>,
    selectedUserId: String,
    onUserIdSelected: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = keyAlias.ifBlank { keyName.ifBlank { "Key" } },
                    style = MaterialTheme.typography.titleMedium,
                )
                val keyIdentity = listOf(keyName, keyFingerprint)
                    .filter { it.isNotBlank() }
                    .joinToString(" • ")
                if (keyAlias.isNotBlank() && keyIdentity.isNotBlank()) {
                    Text(
                        text = keyIdentity,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = if (toolSet == ToolSet.PGP) FontFamily.Monospace else null,
                    )
                }
            }
            Badge(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            ) {
                Text(text = keyAlgorithm.name, style = MaterialTheme.typography.labelSmall)
            }
        }

        if (userIds.size > 1) {
            DropdownField(
                modifier = Modifier.fillMaxWidth(),
                items = userIds,
                label = "User ID",
                value = selectedUserId,
                onItemSelected = { _, userId -> onUserIdSelected(userId) },
            )
        }
    }
}

@Composable
private fun SaltRow(
    useSalt: Boolean,
    saltIv: String,
    onSaltIvChecked: (Boolean) -> Unit,
    onSaltIvChanged: (String) -> Unit,
    regenSalt: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Checkbox(checked = useSalt, onCheckedChange = onSaltIvChecked)
        Text(text = "Cipher salt", style = MaterialTheme.typography.bodyMedium)
        if (useSalt) {
            OutlinedTextField(
                value = saltIv,
                onValueChange = onSaltIvChanged,
                modifier = Modifier.weight(1f),
                label = { Text("Salt") },
                singleLine = true,
                colors = passmanTextFieldColors(),
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                trailingIcon = {
                    RegeneratePasswordButton(
                        onClick = regenSalt,
                        contentDescription = "Generate new salt",
                    )
                },
            )
        }
    }
}

private val baseCryptActions = listOf(
    CryptAction.ENCRYPT,
    CryptAction.DECRYPT,
    CryptAction.SIGN,
    CryptAction.VERIFY,
)

private val targetOptions = listOf(false to "Text", true to "File")

private fun CryptAction.baseAction(): CryptAction = when (this) {
    CryptAction.ENCRYPT_AND_SIGN -> CryptAction.ENCRYPT
    CryptAction.DECRYPT_AND_VERIFY -> CryptAction.DECRYPT
    else -> this
}

private fun CryptAction.combinedAction(): CryptAction? = when (this) {
    CryptAction.ENCRYPT -> CryptAction.ENCRYPT_AND_SIGN
    CryptAction.DECRYPT -> CryptAction.DECRYPT_AND_VERIFY
    else -> null
}

private fun CryptAction.requiresPassword(): Boolean = when (this) {
    CryptAction.DECRYPT,
    CryptAction.SIGN,
    CryptAction.ENCRYPT_AND_SIGN,
    CryptAction.DECRYPT_AND_VERIFY,
    -> true

    CryptAction.ENCRYPT,
    CryptAction.VERIFY,
    -> false
}

private fun CryptAction.requiresSignature(): Boolean = this == CryptAction.VERIFY || this == CryptAction.DECRYPT_AND_VERIFY

private fun CryptAction.label(): String = when (this) {
    CryptAction.ENCRYPT -> "Encrypt"
    CryptAction.DECRYPT -> "Decrypt"
    CryptAction.SIGN -> "Sign"
    CryptAction.VERIFY -> "Verify"
    CryptAction.ENCRYPT_AND_SIGN -> "Encrypt & sign"
    CryptAction.DECRYPT_AND_VERIFY -> "Decrypt & verify"
}

private fun CryptAction.buttonLabel(): String = label()

private fun CryptAction.inputLabel(): String = when (baseAction()) {
    CryptAction.ENCRYPT,
    CryptAction.SIGN,
    -> "Message"

    CryptAction.DECRYPT -> "Ciphertext"
    CryptAction.VERIFY -> "Signed message"
    else -> error("Combined actions resolve to a base action")
}

private fun CryptAction.inputPlaceholder(): String = when (this) {
    CryptAction.ENCRYPT,
    CryptAction.ENCRYPT_AND_SIGN,
    -> "Type or paste the text to encrypt"

    CryptAction.DECRYPT -> "Paste the armored message to decrypt"
    CryptAction.DECRYPT_AND_VERIFY -> "Paste the armored message to decrypt and verify"
    CryptAction.SIGN -> "Type or paste the message to sign"
    CryptAction.VERIFY -> "Paste the signed message to verify"
}
