package ai.passman.platform.prefs.impl

import ai.passman.platform.service.ExpiringClipboard
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.repository.ClipboardPreferences

/**
 * The stored clipboard preference, plus the one side effect persisting it has to have: turning the
 * expiry off has to reach the clear that is already scheduled.
 *
 * Writing the flag alone leaves a pending timer running, and it fires — so the user flips the
 * switch off, watches the clipboard be emptied anyway a few seconds later, and reasonably concludes
 * the setting does nothing. Opting out has to mean the copy already on the clipboard is left alone
 * from that moment on.
 *
 * A decorator rather than a call from the view model or a use-case: [ClipboardPreferences] is a
 * domain contract and stays free of any of this, the coordinator is a platform object no layer
 * above `data` is allowed to hold, and both halves of this class already live in
 * `data/local/platform`. Whoever persists the setting gets the cancellation, including callers that
 * have never heard of the clipboard coordinator.
 *
 * Turning it *on* needs no counterpart: with nothing scheduled there is nothing to schedule
 * retroactively, and the next copy reads the new value. And disabling never clears the clipboard —
 * whatever is on it is now the user's to keep.
 */
class ExpiryAwareClipboardPreferences(
    private val stored: ClipboardPreferences,
    private val clipboard: ExpiringClipboard,
) : ClipboardPreferences {

    override suspend fun getExpiry(): ClipboardExpiry = stored.getExpiry()

    override suspend fun setExpiry(expiry: ClipboardExpiry) {
        stored.setExpiry(expiry)
        // After the store, so the coordinator's own defence-in-depth re-read at fire time cannot
        // see a stale "enabled" if the cancellation is ever lost.
        if (!expiry.enabled) clipboard.onExpiryDisabled()
    }
}
