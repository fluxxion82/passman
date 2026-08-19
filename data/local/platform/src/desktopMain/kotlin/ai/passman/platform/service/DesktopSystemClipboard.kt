package ai.passman.platform.service

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.StringSelection
import java.awt.datatransfer.Transferable

/**
 * The AWT system clipboard.
 *
 * AWT hands out the answer this needs for free. `setContents(transferable, owner)` records an owner
 * alongside the data, and the toolkit calls [ClipboardOwner.lostOwnership] on it the moment
 * anything else — another window, another process, or a later write of our own — takes the
 * clipboard. So "is this still our clip?" is a flag flipped by the platform, with no read of the
 * contents anywhere: [SystemClipboard] has no read to call.
 *
 * The toolkit's promptness is what bounds this. Ownership loss reaches the owner asynchronously —
 * AWT hands the callback to the event queue rather than calling it inline, and the underlying
 * signal is itself an event (an X11 selection notice, the macOS pasteboard change count, the
 * Windows viewer chain), so the flag can lag the actual change. It lags in the direction of still
 * claiming ownership, which is why the check is scheduled seconds after the write rather than
 * moments after it, and why the worst case is a clear issued against a clip that changed a
 * heartbeat ago — the bounded race [ExpiringClipboard] documents, not a new one.
 *
 * @param clipboard resolved per call rather than held: the toolkit's clipboard is a per-display
 * object and this class is constructed once at startup. Overridden in tests with a plain
 * [Clipboard], which behaves identically for ownership and needs no display.
 */
internal class DesktopSystemClipboard(
    private val clipboard: () -> Clipboard = { Toolkit.getDefaultToolkit().systemClipboard },
) : SystemClipboard {

    override fun write(text: String): ClipToken {
        val token = OwnedClip()
        clipboard().setContents(StringSelection(text), token)
        return token
    }

    /**
     * AWT has no "empty the clipboard" call — ownership always belongs to somebody — so the
     * password is replaced with an empty selection, which is what a cleared clipboard pastes as.
     */
    override fun clear() {
        clipboard().setContents(StringSelection(""), null)
    }

    /**
     * Both the owner AWT calls back and the token [ExpiringClipboard] later questions. One object
     * for both halves so there is nothing to look up, and no map of live writes to leak or evict.
     */
    private class OwnedClip : ClipboardOwner, ClipToken {
        /** Written by the AWT event thread, read by the expiry's coroutine. */
        @Volatile
        private var owned = true

        override fun lostOwnership(clipboard: Clipboard, contents: Transferable) {
            owned = false
        }

        override fun stillOurs(): Boolean = owned
    }
}
