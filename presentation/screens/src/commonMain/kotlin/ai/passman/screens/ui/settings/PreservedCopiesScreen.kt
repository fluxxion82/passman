package ai.passman.screens.ui.settings

import ai.passman.design.core.button.PassmanSecondaryButton
import ai.passman.design.dialog.ConfirmDeleteDialog
import ai.passman.design.dialog.ConfirmShareDialog
import ai.passman.design.dialog.MasterPasswordDialog
import ai.passman.design.util.formatDateTime
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.viewmodel.sync.PreservedCopiesViewModel
import ai.passman.viewmodel.sync.syncArtifactLabel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * The versions an inbound sync displaced, and the only place they can be reached.
 *
 * Sync merges artifact directories by filename, so it cannot tell a newer version of the same
 * artifact from a different artifact that happens to share a name. Rather than guess, it moves what
 * it is about to replace into a conflict store — which, until this screen, meant PGP secret rings
 * and PKCS#12 keystores accumulating somewhere nothing in the app could list, restore or delete.
 *
 * Structured like [SyncActivityScreen]: no [androidx.compose.material3.Scaffold] of its own, since
 * the app supplies one around the whole nav host, and [navController] is taken and unused so every
 * `composable<Route> { }` block in `settingsGraph` calls its screen the same shape.
 */
@Composable
fun PreservedCopiesScreen(
    navController: NavController,
    presenter: PreservedCopiesViewModel,
    snackbarHostState: SnackbarHostState,
) {
    val copies by presenter.copies.collectAsState()
    val pendingRestore by presenter.pendingRestore.collectAsState()
    val pendingDelete by presenter.pendingDelete.collectAsState()
    val pendingShare by presenter.pendingShare.collectAsState()
    val pendingExportPassword by presenter.pendingExportPassword.collectAsState()
    val exportPasswordError by presenter.exportPasswordError.collectAsState()

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    // Not ConfirmDeleteDialog: that renders its confirm label in the error colour, which is the
    // app's vocabulary for destroying something. A restore destroys nothing — it swaps, and the
    // version it displaces is preserved in turn.
    pendingRestore?.let { copy ->
        AlertDialog(
            onDismissRequest = presenter::onRestoreDismissed,
            title = { Text("Restore this version?") },
            text = {
                Text(
                    "\"${copy.originalName}\" becomes the version this device uses for " +
                        "${syncArtifactLabel(copy.artifact)}. The version in place now is moved here " +
                        "in its place, so you can swap back.",
                )
            },
            confirmButton = {
                TextButton(onClick = presenter::onRestoreConfirmed) { Text("Restore") }
            },
            dismissButton = {
                TextButton(onClick = presenter::onRestoreDismissed) { Text("Cancel") }
            },
        )
    }

    pendingDelete?.let { copy ->
        ConfirmDeleteDialog(
            title = "Delete this version permanently?",
            message = "\"${copy.originalName}\" is deleted from this device for good. This cannot be " +
                "undone, and it is not backed up anywhere — if this file holds a private key, these " +
                "may be the only bytes of it left.",
            onConfirm = presenter::onDeleteConfirmed,
            onDismiss = presenter::onDeleteDismissed,
            confirmLabel = "Delete permanently",
        )
    }

    pendingExportPassword?.let { copy ->
        MasterPasswordDialog(
            title = "Confirm it's you",
            message = "Enter your master password to export \"${copy.originalName}\". This file may " +
                "hold a private key, so it is not handed to another app without checking.",
            error = exportPasswordError,
            onConfirm = presenter::onExportPasswordEntered,
            onDismiss = presenter::onExportPasswordDismissed,
        )
    }

    pendingShare?.let { request ->
        ConfirmShareDialog(
            // The stored filename is content-addressed and means nothing to the user; the path it
            // was displaced from is the name they are looking at in the list.
            fileName = request.displayName,
            kind = request.kind,
            onConfirm = presenter::onShareConfirmed,
            onDismiss = presenter::onShareDismissed,
        )
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(text = "Replaced Versions", fontWeight = FontWeight.SemiBold, fontSize = 18.sp)
        Text(
            text = "When a sync brought in a file that would have replaced one of yours, the version " +
                "already here was kept instead of overwritten. Nothing was lost — these are those " +
                "versions.",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        if (copies.isEmpty()) {
            Text(
                text = "No sync has replaced anything on this device.",
                color = MaterialTheme.colorScheme.onSurface,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                contentPadding = PaddingValues(vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                // Keyed on artifact and id, without the index. The id is unique within one store
                // and the artifact separates the two stores, so the pair is already unique — and
                // folding in the index would shift every key when a row is restored or deleted,
                // which is the opposite of what a key is for.
                items(copies, key = { copy -> "${copy.artifact}-${copy.id}" }) { copy ->
                    PreservedCopyRow(
                        copy = copy,
                        onRestore = { presenter.onRestoreClicked(copy) },
                        onExport = { presenter.onExportClicked(copy) },
                        onDelete = { presenter.onDeleteClicked(copy) },
                    )
                }
            }
        }
    }
}

@Composable
private fun PreservedCopyRow(
    copy: PreservedCopy,
    onRestore: () -> Unit,
    onExport: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = copy.originalName,
                fontWeight = FontWeight.SemiBold,
                overflow = TextOverflow.Ellipsis,
                maxLines = 2,
            )
            Text(
                text = syncArtifactLabel(copy.artifact),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface,
            )
            // Shown when the file parses as an OpenPGP ring, absent otherwise — a keystore has no
            // fingerprint, and a ring this build cannot read must still list. Two copies under one
            // filename are the whole reason this screen exists, and the fingerprint is what tells
            // them apart; the filename by definition cannot.
            copy.fingerprint?.let { fingerprint ->
                Text(
                    text = "Fingerprint: $fingerprint",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            copy.algorithm?.let { algorithm ->
                Text(
                    text = "Algorithm: $algorithm",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = formatFileSize(copy.sizeBytes),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface,
            )
            // Said in full because the obvious reading is wrong: this is the timestamp of the
            // version itself, carried across by the move, not the moment sync displaced it.
            Text(
                text = "This version last modified ${formatDateTime(copy.modifiedAt)}",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            // No Restore button when the path this came from was too long to record. The bytes are
            // intact and exporting still works; it is only the destination that is unknown, and a
            // button that wrote to a guessed one would look like it worked while leaving the real
            // artifact untouched.
            if (!copy.restorable) {
                Text(
                    text = "Where this came from was too long to record, so it cannot be put back " +
                        "automatically. Export it and replace the file yourself.",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (copy.restorable) {
                    PassmanSecondaryButton(text = "Restore", onClick = onRestore, fontSize = 12.sp)
                }
                PassmanSecondaryButton(text = "Export", onClick = onExport, fontSize = 12.sp)
                PassmanSecondaryButton(text = "Delete", onClick = onDelete, fontSize = 12.sp)
            }
        }
    }
}

/**
 * Rounded, binary units, no decimals below a megabyte. Local to this screen on purpose: it is the
 * only surface in the app that shows a file size, and a shared helper in `design` would be a
 * one-caller abstraction. Promote it if a second caller appears.
 */
private fun formatFileSize(sizeBytes: Long): String = when {
    sizeBytes < 1024 -> "$sizeBytes B"
    sizeBytes < 1024 * 1024 -> "${sizeBytes / 1024} KB"
    else -> "${sizeBytes / (1024 * 1024)} MB"
}
