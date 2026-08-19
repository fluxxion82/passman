package ai.passman.design.keystore

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.RegeneratePasswordButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanButtonColors

import ai.passman.design.core.passmanTextFieldColors

import ai.passman.design.core.DropdownField
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.TextField
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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

@Composable
@Suppress("MagicNumber")
fun CreateKeyStoreContent(
    keyStoreName: String,
    keystorePassword: String,
    keyAlias: String,
    keyPassword: String,
    keyAliasAlgorithm: KeystoreKeyAlgorithm,
    isSaveStorePassToListChecked: Boolean,
    isSaveKeyPassToListChecked: Boolean,
    isLoading: Boolean,
    onKeystoreNameChanged: (String) -> Unit,
    onPasswordChanged: (String) -> Unit,
    onKeyAliasChanged: (String) -> Unit,
    onKeyPasswordChanged: (String) -> Unit,
    onKeyAlgorithmPicked: (KeystoreKeyAlgorithm) -> Unit,
    onReGenStorePass: () -> Unit,
    onReGenKeyPass: () -> Unit,
    onSaveStorePasswordChecked:(Boolean) -> Unit,
    onSaveKeyPasswordChecked:(Boolean) -> Unit,
    onCreate: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
            .imePadding()
            .verticalScroll(rememberScrollState())
            .formKeyboardNavigation(onSubmit = { onCreate(); true })
    ) {
        var storePasswordVisibility by remember { mutableStateOf(false) }
        var keyPasswordVisibility by remember { mutableStateOf(false) }

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(15.dp, 10.dp, 15.dp, 0.dp),
            value = keyStoreName,
            onValueChange = onKeystoreNameChanged,
            colors = passmanTextFieldColors(),
            label = {
                Text("Keystore name", color = MaterialTheme.colorScheme.secondary)
            },
            singleLine = true,
        )

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(15.dp, 10.dp, 15.dp, 0.dp),
            value = keystorePassword,
            onValueChange = onPasswordChanged,
            colors = passmanTextFieldColors(),
            visualTransformation = if (storePasswordVisibility) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                Row {
                    RegeneratePasswordButton(onClick = onReGenStorePass)
                    PasswordVisibilityToggle(
                        visible = storePasswordVisibility,
                        onToggle = { storePasswordVisibility = !storePasswordVisibility },
                        contentDescription = "keystore password visibility",
                    )
                }
            },
            label = {
                Text("Keystore password", color = MaterialTheme.colorScheme.secondary)
            },
            singleLine = true,
        )

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Start) {
            Checkbox(
                checked = isSaveStorePassToListChecked,
                onCheckedChange = { onSaveStorePasswordChecked(it) }
            )
            Text(
                modifier = Modifier
                    .padding(end = 10.dp),
                text = "Save password to password list."
            )
            Spacer(modifier = Modifier.weight(1f))
        }

        Text(
            modifier = Modifier.align(Alignment.Start).padding(15.dp, 20.dp, 15.dp, 5.dp),
            text = "Initial Key",
            fontWeight = FontWeight.Bold,
        )

        DropdownField(
            modifier = Modifier.fillMaxWidth().padding(15.dp, 10.dp, 15.dp, 0.dp),
            items = KeystoreKeyAlgorithm.entries.filter { it != KeystoreKeyAlgorithm.UNKNOWN } .map { it.name },
            label = "Key Algorithm",
            value = keyAliasAlgorithm.name,
            enabled = true,
            onItemSelected = { _, algoName ->
                onKeyAlgorithmPicked(KeystoreKeyAlgorithm.valueOf(algoName))
            }
        )

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(15.dp, 10.dp, 15.dp, 0.dp),
            value = keyAlias,
            onValueChange = onKeyAliasChanged,
            colors = passmanTextFieldColors(),
            label = {
                Text("Key alias", color = MaterialTheme.colorScheme.secondary)
            },
            singleLine = true,
        )

        TextField(
            modifier = Modifier
                .fillMaxWidth()
                .padding(15.dp, 10.dp, 15.dp, 0.dp),
            value = keyPassword,
            onValueChange = onKeyPasswordChanged,
            colors = passmanTextFieldColors(),
            visualTransformation = if (keyPasswordVisibility) {
                VisualTransformation.None
            } else {
                PasswordVisualTransformation()
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            trailingIcon = {
                Row {
                    RegeneratePasswordButton(onClick = onReGenKeyPass)
                    PasswordVisibilityToggle(
                        visible = keyPasswordVisibility,
                        onToggle = { keyPasswordVisibility = !keyPasswordVisibility },
                        contentDescription = "alias password visibility",
                    )
                }
            },
            label = {
                Text("Alias password", color = MaterialTheme.colorScheme.secondary)
            },
            singleLine = true,
        )

        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Start) {
            Checkbox(
                checked = isSaveKeyPassToListChecked,
                onCheckedChange = { onSaveKeyPasswordChecked(it) }
            )
            Text(
                modifier = Modifier
                    .padding(end = 10.dp),
                text = "Save password to password list."
            )
            Spacer(modifier = Modifier.weight(1f))
        }

        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth()
        ) {
            if (isLoading) {
                CircularProgressIndicator(
                    modifier = Modifier
                        .weight(1f)
                        .wrapContentWidth(Alignment.CenterHorizontally)
                        .padding(20.dp),
                    // The screen root is primary; the spinner's default primary color vanishes on it.
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            } else {
                Button(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(20.dp)
                        .clickable(
                            interactionSource = remember { MutableInteractionSource() },
                            indication = ripple(bounded = false),
                            onClick = { }
                        ),
                    shape = RoundedCornerShape(80),
                    colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
                    onClick = {
                        onCreate()
                    }
                ) {
                    Text(
                        text = "Create",
                        fontSize = 18.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}
