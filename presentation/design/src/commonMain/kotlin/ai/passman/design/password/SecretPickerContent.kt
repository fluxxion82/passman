package ai.passman.design.password

import ai.passman.design.core.formKeyboardNavigation
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog

/**
 * One selectable saved credential.
 *
 * Name and username only — enough to recognise an entry, and nothing that would put a password
 * inside a composition, a recomposition log, or a UI test dump. The picker view model exposes the
 * same three fields as `ai.passman.viewmodel.password.SecretPickerRow`; the screen that
 * hosts both maps between them, since this module cannot see the view-model module.
 */
data class SecretPickerItem(
    val id: String,
    val name: String,
    val username: String,
)

/**
 * [SecretPickerContent] in the container the rest of the app uses for a focused choice — the same
 * `Dialog` + `Card` pairing as `ConfirmDeleteDialog` and the keystore password prompt.
 *
 * It exists so that the PGP and keystore tool screens cannot drift apart: picking a saved password
 * has to look and behave identically on both, and both are asking the same question.
 */
@Composable
fun SecretPickerDialog(
    query: String,
    items: List<SecretPickerItem>,
    onQueryChanged: (String) -> Unit,
    onItemSelected: (String) -> Unit,
    onDismiss: () -> Unit,
    title: String = "Use a saved password",
) {
    Dialog(onDismissRequest = onDismiss) {
        Card {
            SecretPickerContent(
                query = query,
                items = items,
                onQueryChanged = onQueryChanged,
                onItemSelected = onItemSelected,
                onDismiss = onDismiss,
                title = title,
            )
        }
    }
}

/**
 * The saved-password picker: a search box over the user's own vault plus the list it filters.
 *
 * Pure state and callbacks — no Koin lookup, no view model — so the PGP and keystore screens can
 * each host it in whatever container suits them (dialog, sheet, inline panel).
 *
 * [onItemSelected] receives the chosen [SecretPickerItem.id]. The password itself never travels
 * through this composable; the view model resolves the id and hands the secret straight to the
 * requesting screen.
 */
@Composable
fun SecretPickerContent(
    query: String,
    items: List<SecretPickerItem>,
    onQueryChanged: (String) -> Unit,
    onItemSelected: (String) -> Unit,
    onDismiss: () -> Unit,
    modifier: Modifier = Modifier,
    title: String = "Use a saved password",
    emptyMessage: String = "No saved passwords match",
    emptyVaultMessage: String = "No saved passwords yet",
) {
    // The picker opens on the search box: it is the only thing here the user can type into, and
    // the list below it is already filtering as they type.
    val focusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current
    LaunchedEffect(Unit) { focusRequester.requestFocus() }

    // No onSubmit: choosing an entry is a click on a row, and the search field's own Search IME
    // action already consumes Enter. The handler still keeps Tab moving focus inside this
    // dialog's separate composition instead of typing anything.
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.background)
            .formKeyboardNavigation(),
    ) {
        Text(
            modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 8.dp),
            text = title,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Bold,
        )

        TextField(
            value = query,
            onValueChange = onQueryChanged,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .clip(RoundedCornerShape(percent = 50))
                .focusRequester(focusRequester),
            placeholder = {
                Text("Search by name or username", color = MaterialTheme.colorScheme.outline)
            },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Default.Search,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.outline,
                )
            },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    // Decorative trailing icon: Tab skips it, mouse and touch still clear.
                    IconButton(
                        onClick = { onQueryChanged("") },
                        modifier = Modifier.focusProperties { canFocus = false },
                    ) {
                        Icon(
                            imageVector = Icons.Default.Clear,
                            contentDescription = "Clear",
                            tint = MaterialTheme.colorScheme.outline,
                        )
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(percent = 50),
            colors = TextFieldDefaults.colors(
                focusedContainerColor = MaterialTheme.colorScheme.surface,
                unfocusedContainerColor = MaterialTheme.colorScheme.surface,
                disabledContainerColor = MaterialTheme.colorScheme.surface,
                focusedTextColor = MaterialTheme.colorScheme.onSurface,
                unfocusedTextColor = MaterialTheme.colorScheme.onSurface,
                cursorColor = MaterialTheme.colorScheme.onSurface,
                focusedIndicatorColor = Color.Transparent,
                unfocusedIndicatorColor = Color.Transparent,
                disabledIndicatorColor = Color.Transparent,
            ),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Text,
                imeAction = ImeAction.Search,
            ),
            // There is nothing to submit — filtering is live — so the search key only gets the
            // keyboard out of the way of the results it just produced.
            keyboardActions = KeyboardActions(onSearch = { keyboardController?.hide() }),
        )

        if (items.isEmpty()) {
            Text(
                modifier = Modifier.padding(16.dp),
                // A blank query filters nothing, so it always lists the whole vault: no rows plus
                // no query means there is nothing saved, not that the search missed.
                text = if (query.isBlank()) emptyVaultMessage else emptyMessage,
                color = MaterialTheme.colorScheme.outline,
            )
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(max = 320.dp)
                    .padding(top = 8.dp)
                    // Same trick the vault list uses: the gap `spacedBy` leaves between opaque rows
                    // lets the column's own colour through as a hairline rule; outlineVariant is
                    // the divider role in both schemes.
                    .background(MaterialTheme.colorScheme.outlineVariant),
                verticalArrangement = Arrangement.spacedBy(1.dp),
            ) {
                // Keyed by position on purpose: entries that predate the uuid field can share a
                // derived identity when they also share a name and a username, and LazyColumn
                // requires unique keys. Clicks still carry the id.
                items(items = items) { item ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(MaterialTheme.colorScheme.surface)
                            .clickable { onItemSelected(item.id) }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(
                            modifier = Modifier
                                .size(36.dp)
                                .clip(CircleShape)
                                .background(MaterialTheme.colorScheme.primary),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(
                                // Entry names are user-supplied and may be blank or start with a
                                // space, so fall back rather than draw an empty circle.
                                text = item.name.trim().take(1).uppercase().ifEmpty { "?" },
                                color = MaterialTheme.colorScheme.onPrimary,
                                fontWeight = FontWeight.Bold,
                            )
                        }

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {
                            Text(
                                text = item.name,
                                color = MaterialTheme.colorScheme.onSurface,
                                fontWeight = FontWeight.Bold,
                            )
                            if (item.username.isNotBlank()) {
                                Text(
                                    text = item.username,
                                    color = MaterialTheme.colorScheme.outline,
                                    maxLines = 1,
                                )
                            }
                        }
                    }
                }
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth().padding(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Spacer(modifier = Modifier.weight(1f))
            TextButton(onClick = onDismiss) {
                Text(text = "Cancel", color = MaterialTheme.colorScheme.primary)
            }
        }
    }
}
