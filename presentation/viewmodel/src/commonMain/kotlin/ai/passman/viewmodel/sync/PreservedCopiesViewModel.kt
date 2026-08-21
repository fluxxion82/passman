package ai.passman.viewmodel.sync

import ai.passman.domain.base.invoke
import ai.passman.domain.settings.DeletePreservedCopy
import ai.passman.domain.settings.GetPreservedCopies
import ai.passman.domain.settings.GetPreservedCopyPath
import ai.passman.domain.settings.RestorePreservedCopy
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.model.ShareFileKind
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the "Replaced by Sync" recovery screen: the versions an inbound sync moved aside instead of
 * overwriting, and the three things the user can do with one.
 *
 * Every action here reaches real key material, so all three are staged rather than executed on the
 * tap — restore rewrites what is live, delete is final, and export puts a possible secret ring in
 * front of another app. Each has its own pending-state flow so the screen can put exactly one
 * confirmation up, and none of them mutates anything until the matching `on...Confirmed`.
 *
 * The list is re-read after every successful action rather than patched in place. Restore does not
 * simply remove a row: it swaps, preserving whatever it displaces, so the store gains an entry as
 * the restored one leaves it. Only the repository knows what the store holds afterwards.
 */
class PreservedCopiesViewModel(
    private val getPreservedCopies: GetPreservedCopies,
    private val restorePreservedCopy: RestorePreservedCopy,
    private val deletePreservedCopy: DeletePreservedCopy,
    private val getPreservedCopyPath: GetPreservedCopyPath,
    private val shareFile: ShareFile,
) : BaseViewModel() {

    val copies = MutableStateFlow<List<PreservedCopy>>(emptyList())

    val userMessages = Channel<String>(Channel.BUFFERED)

    /** The copy whose restore is waiting on the user's confirmation; null when none is pending. */
    val pendingRestore = MutableStateFlow<PreservedCopy?>(null)

    /** The copy whose deletion is waiting on the user's confirmation; null when none is pending. */
    val pendingDelete = MutableStateFlow<PreservedCopy?>(null)

    /** Export waiting on the user's confirmation dialog; null when none is pending. */
    val pendingShare = MutableStateFlow<ShareFileRequest?>(null)

    init {
        reload()
    }

    fun onRestoreClicked(copy: PreservedCopy) {
        pendingRestore.value = copy
    }

    fun onRestoreDismissed() {
        pendingRestore.value = null
    }

    fun onRestoreConfirmed() {
        val copy = pendingRestore.value ?: return
        pendingRestore.value = null
        viewModelScope.launch {
            if (restorePreservedCopy(copy)) {
                copies.value = getPreservedCopies()
                userMessages.send("Restored ${copy.originalName}")
            } else {
                userMessages.send("Couldn't restore ${copy.originalName} — it may already be gone")
                copies.value = getPreservedCopies()
            }
        }
    }

    fun onDeleteClicked(copy: PreservedCopy) {
        pendingDelete.value = copy
    }

    fun onDeleteDismissed() {
        pendingDelete.value = null
    }

    fun onDeleteConfirmed() {
        val copy = pendingDelete.value ?: return
        pendingDelete.value = null
        viewModelScope.launch {
            if (deletePreservedCopy(copy)) {
                copies.value = getPreservedCopies()
                userMessages.send("Deleted ${copy.originalName}")
            } else {
                userMessages.send("Couldn't delete ${copy.originalName} — it may already be gone")
                copies.value = getPreservedCopies()
            }
        }
    }

    /**
     * Resolves the copy's on-disk path and stages the confirmation. Nothing leaves the app here.
     *
     * Always [ShareFileKind.DisplacedVersion], which is the kind that claims the least. A preserved
     * copy may be a secret ring, a public ring, or an entire keystore, and nothing in the store says
     * which — so the wording must warn without asserting protection the file may not have.
     *
     * Refuses to stage while another confirmation is already up. The path resolves on a coroutine,
     * so without this a tapped Export could raise its dialog on top of a restore or delete the user
     * is still reading, and confirm a different action than the one they think they are answering.
     */
    fun onExportClicked(copy: PreservedCopy) {
        if (pendingRestore.value != null || pendingDelete.value != null || pendingShare.value != null) return
        viewModelScope.launch {
            val path = getPreservedCopyPath(copy)
            if (path == null) {
                userMessages.send("Couldn't export ${copy.originalName} — it may already be gone")
                copies.value = getPreservedCopies()
            } else {
                pendingShare.value = ShareFileRequest(
                    filePath = path,
                    displayName = copy.originalName,
                    kind = ShareFileKind.DisplacedVersion,
                )
            }
        }
    }

    fun onShareConfirmed() {
        val request = pendingShare.value ?: return
        pendingShare.value = null
        viewModelScope.launch {
            if (!shareFile(request)) {
                userMessages.send("Couldn't export ${request.displayName}: the file could not be offered")
            }
        }
    }

    fun onShareDismissed() {
        pendingShare.value = null
    }

    private fun reload() {
        viewModelScope.launch { copies.value = getPreservedCopies() }
    }
}
