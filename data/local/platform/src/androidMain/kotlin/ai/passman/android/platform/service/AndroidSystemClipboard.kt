package ai.passman.android.platform.service

import ai.passman.platform.service.ClipToken
import ai.passman.platform.service.SystemClipboard
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.PersistableBundle
import androidx.core.content.ContextCompat
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The Android system clipboard.
 *
 * Nothing here ever calls `getPrimaryClip()`. From Android 12 that call raises the system's
 * "Passman pasted from your clipboard" notification whenever the clip belongs to another app —
 * which is exactly the case the expiry exists to walk away from, so reading to decide would put a
 * toast on screen precisely when Passman was about to do nothing. Ownership is tracked instead,
 * from two signals that cost nothing and say nothing about content:
 *
 * - **`OnPrimaryClipChangedListener`**, registered once here and never removed (this object lives
 *   as long as the process). Any primary-clip change that is not one of ours means the clipboard
 *   moved on, *even if the new text is identical* to what we wrote.
 * - **`getPrimaryClipDescription()`**, which is explicitly exempt from the Android 12 access
 *   notification — unlike `getPrimaryClip()`, it does not count as reading the clipboard. The
 *   description carries the label and the extras we set, so a generation number put in the extras
 *   at write time comes back to identify our own clip. It carries no content.
 *
 * The two are ANDed, and both default to "not ours", which makes every way either signal can go
 * wrong resolve towards leaving the clipboard alone.
 *
 * ### Swallowing our own change
 *
 * `setPrimaryClip` fires the listener too, so our own write would otherwise look like somebody
 * else's. It is swallowed with a *count*, armed before the write, rather than with a timestamp
 * window: some OEM builds deliver the callback asynchronously and arbitrarily late, and a count
 * still swallows it whenever it arrives, where a window would have expired. `clear()` arms one for
 * the same reason.
 *
 * The two ways that discipline can misfire, and where each lands:
 *
 * - Another app writes in the instant between arming and our own `setPrimaryClip`. Its event is
 *   swallowed as ours and our own event is then counted as foreign, so the token reports *not*
 *   ours. Costs a password a longer stay; costs the user nothing.
 * - A build never fires the listener for our own write. The armed count then swallows the next
 *   genuinely foreign change. That is the dangerous direction, and it is exactly what the
 *   description check is there to catch: a foreign clip does not carry our generation.
 *
 * Clips are also flagged sensitive, so the system clipboard preview (Android 13+) shows dots
 * rather than the password. The key is a string literal on purpose: `ClipDescription`'s constant
 * only exists from API 33, while the app supports 31, and the literal is what the platform reads
 * on every version that honours it.
 *
 * One consequence worth stating: while Passman is in the background, Android declines to describe
 * the clip at all (the API 29+ read restriction covers the description as well as the content), so
 * the token answers "not ours" and nothing is cleared until the app is next in front. That is the
 * same posture the previous read-and-compare implementation ended up with, reached without the
 * notification and without keeping the password around to compare against.
 */
internal class AndroidSystemClipboard(context: Context) : SystemClipboard {

    private val context = context.applicationContext

    private val manager: ClipboardManager?
        get() = ContextCompat.getSystemService(this.context, ClipboardManager::class.java)

    /** Identifies one write of ours, travelling in the clip description's extras and back. */
    private val generation = AtomicLong(0)

    /** Change events we caused ourselves and have yet to see arrive. */
    private val selfChanges = AtomicInteger(0)

    /** Set by any clip change that was not one of ours since the last write. */
    private val clipboardMovedOn = AtomicBoolean(false)

    init {
        manager?.addPrimaryClipChangedListener {
            // getAndUpdate returns the value *before* the update: >0 means this event is one we
            // armed, so consume it; 0 means somebody else has the clipboard now.
            if (selfChanges.getAndUpdate { if (it > 0) it - 1 else 0 } == 0) {
                clipboardMovedOn.set(true)
            }
        }
    }

    override fun write(text: String): ClipToken {
        val generation = generation.incrementAndGet()
        val clip = ClipData.newPlainText(CLIP_LABEL, text).apply {
            description.extras = PersistableBundle().apply {
                putBoolean(EXTRA_IS_SENSITIVE, true)
                putLong(EXTRA_GENERATION, generation)
            }
        }
        // Cleared and armed before the write, so a listener that fires synchronously on this
        // thread is already accounted for by the time it runs.
        clipboardMovedOn.set(false)
        selfChanges.incrementAndGet()
        manager?.setPrimaryClip(clip)
        return AndroidClipToken(generation)
    }

    /** `clearPrimaryClip` has been available since API 28; the app's minimum is 31. */
    override fun clear() {
        selfChanges.incrementAndGet()
        manager?.clearPrimaryClip()
    }

    private inner class AndroidClipToken(private val generation: Long) : ClipToken {
        override fun stillOurs(): Boolean {
            if (clipboardMovedOn.get()) return false
            // Not a clipboard read: the description carries no content and raises no notification.
            val description = try {
                manager?.primaryClipDescription
            } catch (_: SecurityException) {
                null
            } ?: return false
            if (description.label?.toString() != CLIP_LABEL) return false
            return description.extras?.getLong(EXTRA_GENERATION, NO_GENERATION) == generation
        }
    }

    private companion object {
        const val CLIP_LABEL = "passman"

        /** `ClipDescription.EXTRA_IS_SENSITIVE`, spelled out so it also applies on API 31 and 32. */
        const val EXTRA_IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"

        /** Ours, not the platform's. Non-secret by construction: a counter, never the clip. */
        const val EXTRA_GENERATION = "ai.passman.clipboard.generation"

        /** Below the first generation handed out, so a clip without ours can never match one. */
        const val NO_GENERATION = 0L
    }
}
