package ai.passman.platform.service

import java.awt.EventQueue
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The desktop half of the ownership rule, against a real AWT [Clipboard].
 *
 * [ClipboardExpiryTest] drives the coordinator with a fake, which proves what it does with the
 * answer; this proves the answer itself is the one AWT gives. A plain `Clipboard` is the same class
 * the toolkit hands out for the system clipboard and follows the same ownership protocol, so the
 * transfers below exercise the production code path without needing a display.
 */
class DesktopSystemClipboardTest {

    private val awt = Clipboard("test")
    private val clipboard = DesktopSystemClipboard { awt }

    /**
     * AWT hands ownership loss to the event queue rather than calling it inline, so a test that
     * looked immediately after the transfer would be reading the flag before the toolkit had
     * written it. Draining the queue here is what production gets for free by not asking until a
     * timer fires seconds later — and it is the same asynchrony that makes the flag `@Volatile`.
     */
    private fun settle() = EventQueue.invokeAndWait { }

    @Test
    fun `a clip nobody has taken since is still ours`() {
        val token = clipboard.write("hunter2")

        assertTrue(token.stillOurs())
        assertEquals("hunter2", awt.getData(DataFlavor.stringFlavor))
    }

    @Test
    fun `another application taking the clipboard takes the ownership with it`() {
        val token = clipboard.write("hunter2")

        awt.setContents(StringSelection("14 Coronation Street, Manchester"), null)
        settle()

        assertFalse(token.stillOurs())
    }

    /**
     * The clip a content comparison would have got wrong: the same text, placed by somebody else.
     * AWT reports the ownership change regardless of what the new contents happen to say.
     */
    @Test
    fun `an identical clip placed by another application is not ours`() {
        val token = clipboard.write("hunter2")

        awt.setContents(StringSelection("hunter2"), null)
        settle()

        assertFalse(token.stillOurs())
    }

    /**
     * Each write gets its own claim, and the earlier one ends. The coordinator cancels the older
     * timer anyway, but a stale token that still called itself ours would make that cancellation
     * the only thing standing between the user and a clip cleared at the wrong deadline.
     */
    @Test
    fun `our own next write ends the previous write's claim`() {
        val first = clipboard.write("first-secret")
        val second = clipboard.write("second-secret")
        settle()

        assertFalse(first.stillOurs())
        assertTrue(second.stillOurs())
    }

    /** AWT cannot empty a clipboard, so a cleared password reads back as the empty string. */
    @Test
    fun `clearing replaces the password with an empty clip`() {
        clipboard.write("hunter2")

        clipboard.clear()

        assertEquals("", awt.getData(DataFlavor.stringFlavor))
    }
}
