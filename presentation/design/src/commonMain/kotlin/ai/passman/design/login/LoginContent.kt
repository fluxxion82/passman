package ai.passman.design.login

import ai.passman.design.core.PasswordVisibilityToggle
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanButtonColors

import ai.passman.design.core.passmanTextFieldColors
import ai.passman.design.util.autoFocusFormOnShow

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.ripple
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
@OptIn(ExperimentalMaterial3Api::class)
@Suppress("MagicNumber")
fun LoginContent(
    userName: String,
    password: String,
    isLoading: Boolean,
    knownUsernames: List<String> = emptyList(),
    /**
     * Only true when the account named in the field has a biometric enrolment this device can
     * actually use. Defaulted so previews and any caller without the plumbing get the same screen
     * as a device with no sensor.
     */
    canBioAuth: Boolean = false,
    onUsernameChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onLogin: () -> Unit,
    onBioAuth: () -> Unit = {},
) {
    var passwordVisibility by remember { mutableStateOf(false) }
    val usernameFocusRequester = remember { FocusRequester() }
    val passwordFocusRequester = remember { FocusRequester() }
    var suggestionsRequested by remember { mutableStateOf(false) }
    val filteredUsernames = remember(userName, knownUsernames) {
        // An input that exactly equals a known account (the prefill, or a completed pick)
        // should offer the OTHER accounts, not substring-filter them all away.
        val exactMatch = knownUsernames.any { it == userName }
        knownUsernames.filter { username ->
            username != userName &&
                (userName.isBlank() || exactMatch || username.contains(userName, ignoreCase = true))
        }
    }
    // Not gated on field focus: the trailing chevron must open the menu on a fresh,
    // unfocused screen, and losing focus already clears suggestionsRequested below.
    val usernameMenuExpanded = suggestionsRequested && filteredUsernames.isNotEmpty()

    // Desktop only: land keyboard focus on the username field so a returning user can hit Enter
    // (or Tab → type → Enter) without touching the mouse. Focus triggers onFocusChanged below,
    // so the account-suggestions menu may open with it — same as click-focus always did.
    if (autoFocusFormOnShow) {
        LaunchedEffect(Unit) { usernameFocusRequester.requestFocus() }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
            // 100dp matches the welcome screen's DuelOptionContent so the title doesn't
            // jump when navigating; the back bar floats over this screen without insetting it.
            .padding(top = 100.dp)
            // Root-first preview Tab beats the expanded menu anchor's own Tab consume, so Tab
            // always walks username → password → Login; Enter submits from either field. The
            // explicit suggestionsRequested clear is belt-and-braces against the trailing Enter
            // KeyUp re-toggling the menu on the (now unfocused) anchor.
            .formKeyboardNavigation(
                onSubmit = {
                    if (!isLoading) {
                        suggestionsRequested = false
                        onLogin()
                        true
                    } else {
                        false
                    }
                },
            ),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            modifier = Modifier,
            text = "PassMan", // stringResource(id = R.string.app_name),
            color = MaterialTheme.colorScheme.onPrimary,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
        )

        ExposedDropdownMenuBox(
            expanded = usernameMenuExpanded,
            // Anchor taps and the box's BackHandler both route here; a no-op strands the menu
            // closed and swallows system back while it is open.
            onExpandedChange = { suggestionsRequested = it },
        ) {
            TextField(
                modifier = Modifier
                    .padding(0.dp, 50.dp, 0.dp, 0.dp)
                    .menuAnchor(MenuAnchorType.PrimaryEditable)
                    .focusRequester(usernameFocusRequester)
                    .onFocusChanged { suggestionsRequested = it.isFocused },
                value = userName,
                onValueChange = {
                    suggestionsRequested = true
                    onUsernameChange(it)
                },
                colors = passmanTextFieldColors(),
                label = {
                    Text("Username", color = MaterialTheme.colorScheme.onSurface) // stringResource(R.string.username_hint)
                },
                trailingIcon = {
                    if (knownUsernames.size > 1) {
                        ExposedDropdownMenuDefaults.TrailingIcon(
                            expanded = usernameMenuExpanded,
                            modifier = Modifier.menuAnchor(MenuAnchorType.SecondaryEditable),
                        )
                    }
                },
                // singleLine (not maxLines=1) so a hardware Enter runs the field's no-op IME
                // action and bubbles up to formKeyboardNavigation instead of committing "\n".
                singleLine = true,
            )

            // Desktop keyboard navigation into this focusable popup is unsupported: M3 focus
            // handoff blurs the anchor and closes the menu through onFocusChanged.
            // Styling params are additive only — the stock panel had no border and near-zero
            // contrast against the anchor's surface (1.17:1 light / 1.10:1 dark), so the border
            // and shadow carry the panel's shape. This screen's backdrop is the primary blue:
            // the border reads 4.05:1 inward against the smoke fill (light) / 5.79:1 (ash on
            // the dark panel), while the outer edge against primary is carried by the 6dp
            // shadow rather than the border (steel on deepSkyBlue is only 2.23:1).
            ExposedDropdownMenu(
                expanded = usernameMenuExpanded,
                onDismissRequest = { suggestionsRequested = false },
                shape = MaterialTheme.shapes.medium,
                // Matches MenuDefaults today; pinned so a token-role change upstream cannot
                // silently retint the panel.
                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                shadowElevation = 6.dp,
                border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            ) {
                filteredUsernames.forEach { username ->
                    DropdownMenuItem(
                        text = { Text(username, color = MaterialTheme.colorScheme.onSurface) },
                        onClick = {
                            onUsernameChange(username)
                            suggestionsRequested = false
                            passwordFocusRequester.requestFocus()
                        },
                    )
                }
            }
        }

        TextField(
            modifier = Modifier
                .padding(0.dp, 10.dp, 0.dp, 0.dp)
                .focusRequester(passwordFocusRequester)
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
                PasswordVisibilityToggle(
                    visible = passwordVisibility,
                    onToggle = { passwordVisibility = !passwordVisibility },
                    contentDescription = "password visibility",
                )
            },
            label = {
                Text("Password", color = MaterialTheme.colorScheme.onSurface) // stringResource(R.string.password_hint)
            },
            singleLine = true,
        )

        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier
                    .wrapContentSize()
                    .padding(start = 50.dp, top = 50.dp, end = 50.dp),
                // The screen root is primary; the spinner's default primary color vanishes on it.
                color = MaterialTheme.colorScheme.onPrimary,
            )
        } else {
            val focusManager = LocalFocusManager.current
            Button(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(start = 50.dp, top = 50.dp, end = 50.dp)
                    .clickable(
                        interactionSource = remember { MutableInteractionSource() },
                        indication = ripple(bounded = false),
                        onClick = {}
                    ),
                shape = RoundedCornerShape(80),
                colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
                onClick = {
                    focusManager.clearFocus()
                    onLogin()
                }
            ) {
                Text(
                    text = "Login", // stringResource(R.string.login)
                    fontSize = 18.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold
                )
            }

            if (canBioAuth) {
                Button(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = 50.dp, top = 10.dp, end = 50.dp),
                    shape = RoundedCornerShape(80),
                    colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
                    onClick = {
                        // Same focus clear as the Login button: the system prompt takes the window,
                        // and returning to a screen with a stale soft keyboard over it is jarring.
                        focusManager.clearFocus()
                        onBioAuth()
                    },
                ) {
                    Text(
                        text = "Unlock with biometrics",
                        fontSize = 18.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold,
                    )
                }
            }
        }
    }
}
