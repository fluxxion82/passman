package ai.passman.platform.service

import ai.passman.logging.KLogger
import ai.passman.domain.settings.model.ShareFileRequest
import ai.passman.domain.settings.service.SettingsService
import java.awt.EventQueue
import java.io.File
import javax.swing.JFileChooser
import javax.swing.JOptionPane
import javax.swing.filechooser.FileSystemView
import kotlin.coroutines.resume
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

class DesktopSettingsService(
    private val clipboard: ExpiringClipboard,
) : SettingsService {
    override suspend fun goToBluetoothSettings() {

    }

    /** Expiry, and the rule about only clearing our own clip, live in [ExpiringClipboard]. */
    override suspend fun copyToClipboard(text: String) {
        clipboard.copy(text)
    }

    /** Desktop "share" is save-as: pick a destination, copy the file there. */
    override suspend fun shareFile(request: ShareFileRequest): Boolean {
        val source = File(request.filePath)
        if (!source.isFile) {
            KLogger.e { "shareFile: not a file: ${request.filePath}" }
            return false
        }
        // A cancelled chooser is the user's decision, not a failure.
        val destination = chooseDestination(source.name, request.shareTitle) ?: return true
        return runCatching {
            withContext(Dispatchers.IO) {
                // copyTo(overwrite) truncates the destination first: pointed back at the source
                // itself it would destroy the file before failing the copy.
                if (destination.canonicalFile == source.canonicalFile) {
                    KLogger.e { "shareFile: destination is the source file, nothing to copy" }
                    false
                } else {
                    source.copyTo(destination, overwrite = true)
                    true
                }
            }
        }.getOrElse {
            if (it is CancellationException) throw it
            KLogger.e(it) { "shareFile: failed to copy ${source.name} to ${destination.absolutePath}" }
            false
        }
    }

    /**
     * Swing may only be touched on the AWT event thread, and the caller's dispatcher is not
     * guaranteed to be it. invokeLater + suspension works from any thread — unlike invokeAndWait,
     * which throws when the caller already IS the event thread (Compose desktop's Main).
     */
    private suspend fun chooseDestination(fileName: String, dialogTitle: String): File? =
        suspendCancellableCoroutine { continuation ->
            // Written and read only on the event thread, so the handoff is race-free.
            var openChooser: JFileChooser? = null
            continuation.invokeOnCancellation {
                // Best effort: close a still-showing dialog so it doesn't outlive the caller.
                // showSaveDialog then returns CANCEL_OPTION; the resume is skipped (isActive).
                EventQueue.invokeLater { openChooser?.cancelSelection() }
            }
            EventQueue.invokeLater {
                val chosen = runCatching {
                    val chooser = object : JFileChooser(FileSystemView.getFileSystemView().homeDirectory) {
                        // Save mode approves an existing file without asking.
                        override fun approveSelection() {
                            if (selectedFile?.exists() == true) {
                                val replace = JOptionPane.showConfirmDialog(
                                    this,
                                    "${selectedFile.name} already exists. Replace it?",
                                    "Replace file?",
                                    JOptionPane.YES_NO_OPTION,
                                )
                                if (replace != JOptionPane.YES_OPTION) return
                            }
                            super.approveSelection()
                        }
                    }
                    chooser.dialogTitle = dialogTitle
                    chooser.selectedFile = File(chooser.currentDirectory, fileName)
                    openChooser = chooser
                    if (chooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
                        chooser.selectedFile
                    } else {
                        null
                    }
                }.getOrElse {
                    KLogger.e(it) { "shareFile: save dialog failed" }
                    null
                }
                openChooser = null
                if (continuation.isActive) continuation.resume(chosen)
            }
        }
}
