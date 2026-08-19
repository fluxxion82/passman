package ai.passman.design.pass

import ai.passman.design.util.formatDate
import ai.passman.domain.password.model.PasswordEntry
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
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
import androidx.compose.ui.graphics.compositeOver
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PassMgmtContent(
    passphrases: List<PasswordEntry>,
    searchVisible: Boolean,
    searchQuery: String,
    // Entry uuids, not display ordinals: a selection has to survive the renumbering that the
    // next read performs.
    selectedIds: Set<String>,
    onSearchQueryChanged: (String) -> Unit,
    onEntryClick: (String) -> Unit,
    onEntryLongPress: (String) -> Unit,
) {
    val selectedTint = MaterialTheme.colorScheme.primary
        .copy(alpha = 0.2f)
        .compositeOver(MaterialTheme.colorScheme.surface)
    Column {
        AnimatedVisibility(visible = searchVisible) {
            val focusRequester = remember { FocusRequester() }
            LaunchedEffect(Unit) { focusRequester.requestFocus() }

            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.primary)
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                TextField(
                    value = searchQuery,
                    onValueChange = onSearchQueryChanged,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(percent = 50))
                        .focusRequester(focusRequester),
                    placeholder = { Text("Search passwords", color = MaterialTheme.colorScheme.outline) },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Default.Search,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.outline,
                        )
                    },
                    trailingIcon = {
                        if (searchQuery.isNotEmpty()) {
                            // Decorative trailing icon: Tab skips it, mouse and touch still clear.
                            IconButton(
                                onClick = { onSearchQueryChanged("") },
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
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxWidth()
                // The gap `spacedBy` leaves between opaque rows lets the column's own colour
                // through as a hairline rule; outlineVariant is the divider role in both schemes.
                .background(MaterialTheme.colorScheme.outlineVariant),
            verticalArrangement = Arrangement.spacedBy(1.dp),
        ) {
            items(
                items = passphrases,
                // The display ordinal, not the uuid: LazyColumn requires unique keys, and two rows
                // that predate the uuid field can share a derived identity when they also share a
                // name and a username. Ordinals are unique on every branch that reaches the UI —
                // pinned by "the retry must not stamp a stale ordinal onto the published vault" in
                // EntryIdentityTest. Clicks and selection still carry `pass.uuid`.
                key = { it.id },
            ) { pass ->
                val selected = pass.uuid in selectedIds
                val rowColor = if (selected) selectedTint else MaterialTheme.colorScheme.surface
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(rowColor)
                        .combinedClickable(
                            interactionSource = null,
                            indication = ripple(
                                bounded = true,
                                color = MaterialTheme.colorScheme.primary,
                            ),
                            onClick = { onEntryClick(pass.uuid) },
                            onLongClick = { onEntryLongPress(pass.uuid) },
                        )
                        .padding(start = 10.dp, top = 20.dp, bottom = 20.dp, end = 10.dp),
                ) {
                    Text(
                        // The only weighted child, and there is deliberately no Spacer beside it.
                        // A Row measures its unweighted children first, so the date always gets its
                        // full width and sits flush against the row's end, and the name takes
                        // whatever is left and ellipsizes. An earlier version had this weighted
                        // alongside a `Spacer(weight(1f))`: two weights split the leftover space
                        // evenly, which parked the date at "name width plus half the remainder" —
                        // a different x for every row, and never the right edge.
                        modifier = Modifier
                            .weight(1f)
                            .align(Alignment.CenterVertically),
                        text = pass.entryName,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )

                    Text(
                        modifier = Modifier
                            .padding(start = 8.dp)
                            .align(Alignment.Bottom),
                        // dateCreated, which despite its name is the last-edited stamp
                        // (PasswordEntry's KDoc) — deliberately not swapped for createdAt, since
                        // this column has always shown this value and users read it that way. It
                        // stays a bare date by owner preference: the details screen spells out
                        // created vs last edited, so the list does not have to carry the word.
                        text = formatDate(pass.dateCreated),
                        color = MaterialTheme.colorScheme.onSurface,
                        textAlign = TextAlign.End,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}
