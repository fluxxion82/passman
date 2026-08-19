package ai.passman.design.pass

import ai.passman.design.core.passmanTextFieldColors
import ai.passman.design.util.formatDateTime
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.EntryActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The seed input shown while adding or editing an entry. [onScanImageClicked] opens the image
 * picker; [onScanCameraClicked] opens the live scanner and is null where the platform has none.
 */
@Composable
fun TotpSeedField(
    value: String,
    onChanged: (String) -> Unit,
    onScanImageClicked: () -> Unit,
    onScanCameraClicked: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    TextField(
        modifier = modifier
            .height(IntrinsicSize.Min)
            .fillMaxWidth()
            .padding(0.dp, 5.dp, 0.dp, 5.dp),
        value = value,
        onValueChange = onChanged,
        colors = passmanTextFieldColors(),
        singleLine = true,
        label = {
            Text(
                text = "TOTP secret (base32 or otpauth link)",
                color = MaterialTheme.colorScheme.onSurface,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
            )
        },
        trailingIcon = {
            Row {
                IconButton(onClick = onScanImageClicked) {
                    Icon(imageVector = Icons.Filled.Image, "import QR from image")
                }
                if (onScanCameraClicked != null) {
                    IconButton(onClick = onScanCameraClicked) {
                        Icon(imageVector = Icons.Filled.QrCodeScanner, "scan QR with camera")
                    }
                }
            }
        },
    )
}

/** The rolling one-time code with its countdown; shown on the details screen in view mode. */
@Composable
fun TotpCodeDisplay(
    totpCode: GenerateTotpCode.TotpCode,
    onCopyClicked: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.padding(0.dp, 5.dp, 0.dp, 5.dp)) {
        Text(
            text = "one-time code",
            color = MaterialTheme.colorScheme.onSurface,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                // 287082 reads as "287 082"; odd lengths keep the larger half first.
                text = totpCode.code.let { it.take((it.length + 1) / 2) + " " + it.drop((it.length + 1) / 2) },
                color = MaterialTheme.colorScheme.primary,
                fontSize = 28.sp,
                fontFamily = FontFamily.Monospace,
            )
            CircularProgressIndicator(
                progress = { totpCode.secondsRemaining.toFloat() / totpCode.periodSeconds },
                modifier = Modifier.padding(start = 12.dp).size(20.dp),
                strokeWidth = 2.dp,
            )
            IconButton(onClick = onCopyClicked) {
                Icon(imageVector = Icons.Filled.ContentCopy, "copy one-time code")
            }
        }
    }
}

/**
 * The user-defined fields of one entry. In [editMode] each row is editable with a secrecy toggle
 * and a remove button; in view mode secret values stay concealed behind an eye toggle.
 */
@Composable
fun CustomFieldsSection(
    fields: List<CustomField>,
    editMode: Boolean,
    onLabelChanged: (Int, String) -> Unit,
    onValueChanged: (Int, String) -> Unit,
    onSecretToggled: (Int) -> Unit,
    onRemoveClicked: (Int) -> Unit,
    onAddClicked: () -> Unit,
    onCopyClicked: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        fields.forEachIndexed { index, field ->
            if (editMode) {
                EditableCustomFieldRow(index, field, onLabelChanged, onValueChanged, onSecretToggled, onRemoveClicked)
            } else {
                ReadOnlyCustomFieldRow(index, field, onCopyClicked)
            }
        }
        if (editMode) {
            TextButton(onClick = onAddClicked) {
                Icon(imageVector = Icons.Filled.Add, "add custom field")
                Text(text = "Add field", modifier = Modifier.padding(start = 4.dp))
            }
        }
    }
}

@Composable
private fun EditableCustomFieldRow(
    index: Int,
    field: CustomField,
    onLabelChanged: (Int, String) -> Unit,
    onValueChanged: (Int, String) -> Unit,
    onSecretToggled: (Int) -> Unit,
    onRemoveClicked: (Int) -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier.fillMaxWidth().padding(0.dp, 5.dp, 0.dp, 5.dp),
    ) {
        TextField(
            modifier = Modifier.weight(0.4f),
            value = field.label,
            onValueChange = { onLabelChanged(index, it) },
            colors = passmanTextFieldColors(),
            singleLine = true,
            label = { Text("label", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp) },
        )
        TextField(
            modifier = Modifier.weight(0.6f),
            value = field.value,
            onValueChange = { onValueChanged(index, it) },
            colors = passmanTextFieldColors(),
            singleLine = true,
            label = { Text("value", color = MaterialTheme.colorScheme.onSurface, fontSize = 12.sp) },
        )
        IconButton(onClick = { onSecretToggled(index) }) {
            Icon(
                imageVector = if (field.secret) Icons.Filled.Lock else Icons.Filled.LockOpen,
                contentDescription = if (field.secret) "field is secret" else "field is visible",
            )
        }
        IconButton(onClick = { onRemoveClicked(index) }) {
            Icon(imageVector = Icons.Filled.Close, "remove field")
        }
    }
}

@Composable
private fun ReadOnlyCustomFieldRow(
    index: Int,
    field: CustomField,
    onCopyClicked: (Int) -> Unit,
) {
    var revealed by remember(field.label) { mutableStateOf(false) }
    TextField(
        modifier = Modifier
            .height(IntrinsicSize.Min)
            .fillMaxWidth()
            .padding(0.dp, 5.dp, 0.dp, 5.dp),
        value = if (field.secret && !revealed) "•".repeat(8) else field.value,
        onValueChange = {},
        readOnly = true,
        colors = passmanTextFieldColors(),
        singleLine = true,
        label = {
            Text(
                text = field.label,
                color = MaterialTheme.colorScheme.onSurface,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
            )
        },
        trailingIcon = {
            Row {
                if (field.secret) {
                    IconButton(onClick = { revealed = !revealed }) {
                        Icon(
                            imageVector = if (revealed) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = if (revealed) "conceal value" else "reveal value",
                        )
                    }
                }
                IconButton(onClick = { onCopyClicked(index) }) {
                    Icon(imageVector = Icons.Filled.ContentCopy, "copy value")
                }
            }
        },
    )
}

/**
 * Maps an [EntryActivity.kind] to the word shown in the history list.
 *
 * Deliberately a `when` with an `else`, not an exhaustive match over [EntryActivity.KIND_CREATED] /
 * [EntryActivity.KIND_EDITED]. `kind` is a plain `String` precisely so a record written by a future
 * build round-trips through this one (see [EntryActivity]'s KDoc); an exhaustive `when` would compile
 * today and then either throw or drop the row the first time a peer on a newer build syncs in a kind
 * this build has never heard of. "Changed" is that record surviving the trip, not a crash.
 */
internal fun activityKindLabel(kind: String): String = when (kind) {
    EntryActivity.KIND_CREATED -> "Created"
    EntryActivity.KIND_EDITED -> "Edited"
    else -> "Changed"
}

/**
 * One line of entry history: `<when> · <what>`, with the device appended only when known.
 *
 * [EntryActivity.device] is empty for every record this build writes — nothing populates it yet —
 * so an empty value is "unknown", not "no device", and is omitted rather than rendered as a blank
 * trailing segment. A later task starts writing it; this already renders it when present.
 */
@Composable
private fun ActivityRow(record: EntryActivity, modifier: Modifier = Modifier) {
    val text = if (record.device.isNotEmpty()) {
        "${formatDateTime(record.at)} · ${activityKindLabel(record.kind)} · ${record.device}"
    } else {
        "${formatDateTime(record.at)} · ${activityKindLabel(record.kind)}"
    }
    Text(
        text = text,
        modifier = modifier.padding(0.dp, 2.dp, 0.dp, 2.dp),
        color = MaterialTheme.colorScheme.onSurface,
        style = MaterialTheme.typography.bodySmall,
    )
}

/**
 * Read-only history for one entry, shown on the details screen. Never editable and never wired into
 * `formKeyboardNavigation` — it is a record of what happened, not a field.
 *
 * [activity] is sorted here for display, newest first, rather than positionally reversed.
 * `mergeActivity` (`data/local/platform`) does leave the stored list ascending, but
 * `PasswordEntry.activity` deliberately promises no ordering: a vault synced from a build this one
 * has never merged with can hand over a list no local `mergeActivity` has touched, and reversing that
 * positionally would render it in an order that is simply wrong. Sorting a copy is exactly as
 * non-mutating as reversing one — the stored list is never reordered, which is what the merge cares
 * about.
 *
 * A legacy entry synced before this schema step has an empty [activity] and a [createdAt] backfilled
 * equal to [lastEditedAt] (`PasswordEntry.createdAt`'s KDoc). For it this renders the two timestamps
 * and nothing else.
 */
@Composable
fun EntryHistorySection(
    createdAt: Long,
    lastEditedAt: Long,
    activity: List<EntryActivity>,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.padding(0.dp, 10.dp, 0.dp, 0.dp)) {
        HorizontalDivider()
        Text(
            text = "History",
            modifier = Modifier.padding(0.dp, 10.dp, 0.dp, 5.dp),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            text = "Created ${formatDateTime(createdAt)}",
            color = MaterialTheme.colorScheme.onSurface,
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            text = "Last edited ${formatDateTime(lastEditedAt)}",
            color = MaterialTheme.colorScheme.onSurface,
            style = MaterialTheme.typography.bodySmall,
        )
        activity.sortedByDescending { it.at }.forEach { record ->
            ActivityRow(record)
        }
    }
}
