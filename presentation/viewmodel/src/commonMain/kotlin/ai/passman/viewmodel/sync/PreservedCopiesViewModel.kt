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
import ai.passman.domain.user.VerifyMasterPassword
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
    private val verifyMasterPassword: VerifyMasterPassword,
) : BaseViewModel() {

    val copies = MutableStateFlow<List<PreservedCopy>>(emptyList())

    val userMessages = Channel<String>(Channel.BUFFERED)

    /** The copy whose restore is waiting on the user's confirmation; null when none is pending. */
    val pendingRestore = MutableStateFlow<PreservedCopy?>(null)

    /** The copy whose deletion is waiting on the user's confirmation; null when none is pending. */
    val pendingDelete = MutableStateFlow<PreservedCopy?>(null)

    /** Export waiting on the user's confirmation dialog; null when none is pending. */
    val pendingShare = MutableStateFlow<ShareFileRequest?>(null)

    /**
     * The copy whose export is waiting on the master password; null when none is pending.
     *
     * Export is re-authenticated because it is the one action here that puts key material somewhere
     * Passman no longer controls, and the app already refuses to export a live private key without
     * proof. Without this, a displaced secret ring — quite possibly one under a passphrase the user
     * rotated because it leaked — would be the cheapest key material in the app to walk off with.
     */
    val pendingExportPassword = MutableStateFlow<PreservedCopy?>(null)

    /** Message under the password field after a wrong entry; null while nothing is wrong. */
    val exportPasswordError = MutableStateFlow<String?>(null)

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
     * Stages the master-password prompt. Nothing is resolved or exported here.
     *
     * Refuses while another dialog is up, so a tap can never raise a prompt over a confirmation the
     * user is still reading and have them answer a question they were not asked.
     */
    fun onExportClicked(copy: PreservedCopy) {
        if (aDialogIsOpen()) return
        exportPasswordError.value = null
        pendingExportPassword.value = copy
    }

    fun onExportPasswordDismissed() {
        pendingExportPassword.value = null
        exportPasswordError.value = null
    }

    /**
     * Verifies the master password and only then resolves the path and stages the confirmation.
     *
     * The path is resolved after the check rather than before, so a wrong password learns nothing —
     * not even whether the file is still there.
     */
    fun onExportPasswordEntered(password: String) {
        val copy = pendingExportPassword.value ?: return
        viewModelScope.launch {
            if (!verifyMasterPassword(password)) {
                exportPasswordError.value = "That is not your master password."
                return@launch
            }
            pendingExportPassword.value = null
            exportPasswordError.value = null
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

    private fun aDialogIsOpen(): Boolean =
        pendingRestore.value != null ||
            pendingDelete.value != null ||
            pendingShare.value != null ||
            pendingExportPassword.value != null

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
