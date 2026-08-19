package ai.passman.platform.service

import ai.passman.domain.settings.repository.ClipboardPreferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Puts text on the system clipboard and takes it back off again once the expiry elapses.
 *
 * All of the behaviour lives here rather than in the platform services, so Android and desktop
 * share one timer and one cancellation rule, and the desktop tests exercise the code both
 * platforms actually run. The platform adapters are thin on purpose: they answer "is this still
 * our clip?" and nothing else.
 *
 * Three rules do the real work:
 *
 * 1. **Clear only what we still own.** The clear happens only while the [ClipToken] from our own
 *    write still reports the clipboard as ours. Not "still holds the same text" — ownership. An
 *    identical clip somebody else wrote in the meantime is *theirs*, and is left alone. Nothing
 *    reads the clipboard's contents, on any platform, at any point: that is what keeps the
 *    Android 12+ "pasted from your clipboard" notification from firing for a clip we only wanted
 *    to leave alone, and it is why no copy of the password is kept here at all.
 * 2. **One pending clear.** A second copy cancels the first copy's timer outright. Ownership alone
 *    is not enough here: a stale timer that woke up owning the *current* clip would clear the newer
 *    clip at the older deadline, seconds after the user copied it.
 * 3. **Off means off.** [onExpiryDisabled] cancels a pending clear the moment the user turns the
 *    setting off, and the setting is re-read at fire time as a second line of defence.
 *
 * ### The bounded race
 *
 * The guarantee is best-effort, not absolute. Between the ownership check and the clear itself
 * another process can take the clipboard, and no system clipboard API on any of these platforms
 * offers a compare-and-clear to close that window — clearing is unconditional once issued. The
 * window is kept to the two adjacent statements in [clearIfStillOurs] and nothing suspends inside
 * it, but it is not zero. The failure direction is stated plainly: in that microsecond window
 * Passman may clear a clip written by somebody else. It cannot go the other way and leave a
 * password behind that it believed it had cleared.
 *
 * Ownership reporting is itself best-effort per platform (AWT can deliver ownership loss late;
 * Android may decline to describe the clip at all while Passman is in the background). Both
 * failure modes are wired to answer "not ours", so they cost a password a longer stay on the
 * clipboard rather than costing the user their clip.
 */
class ExpiringClipboard(
    private val clipboard: SystemClipboard,
    private val preferences: ClipboardPreferences,
    private val scope: CoroutineScope,
) {
    /** Serialises copy against the pending clear, so a clear can never straddle a new copy. */
    private val lock = Mutex()
    private var pendingClear: Job? = null

    /**
     * The clip the pending clear was scheduled for. A token, not a secret: it carries a platform
     * ownership handle and nothing else, so there is no second place the password lives and
     * nothing here to wipe.
     */
    private var pendingClip: ClipToken? = null

    suspend fun copy(text: String) = lock.withLock {
        cancelPending()
        val token = clipboard.write(text)
        // The setting is read *inside* the critical section on purpose. Awaiting it before taking
        // the lock lets two rapid copies resume in the opposite order to the one they were made
        // in, and the older copy then wins both the clipboard and the timer.
        val expiry = preferences.getExpiry()
        if (expiry.enabled) {
            pendingClip = token
            pendingClear = scope.launch {
                // Non-positive durations are normalised away by the preferences store; honour
                // whatever is configured rather than second-guessing it here.
                delay(expiry.duration)
                clearIfStillOurs(token)
            }
        }
    }

    /**
     * The user turned the expiry off. A pending clear is cancelled outright and the clip it was
     * scheduled for is dropped — opting out has to reach the timer that is already running, not
     * merely the store the next copy will consult.
     */
    suspend fun onExpiryDisabled() = lock.withLock { cancelPending() }

    private suspend fun clearIfStillOurs(token: ClipToken) = lock.withLock {
        // A newer copy already replaced this clip; its own timer owns what happens next.
        if (pendingClip !== token) return@withLock

        // Defence in depth. [onExpiryDisabled] should already have cancelled this job, so reaching
        // here with the expiry off means that notification did not arrive — decline anyway.
        val enabled = preferences.getExpiry().enabled

        // Checked as late as possible: nothing suspends between proving the clip is ours and
        // taking it away. See "the bounded race" above for what that still cannot promise.
        if (enabled && token.stillOurs()) clipboard.clear()
        forget()
    }

    /** Called from the firing timer itself, so it must not cancel the job it is running on. */
    private fun forget() {
        pendingClip = null
        pendingClear = null
    }

    private fun cancelPending() {
        pendingClear?.cancel()
        forget()
    }
}
