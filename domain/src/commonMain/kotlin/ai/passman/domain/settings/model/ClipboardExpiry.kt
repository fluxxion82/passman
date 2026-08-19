package ai.passman.domain.settings.model

import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * How long a secret Passman puts on the system clipboard is allowed to stay there.
 *
 * The duration is stored rather than hard-coded so it can be tuned later without another
 * settings-format change; the toggle is what the user sees. Disabling it is a deliberate opt-out
 * — the clip then behaves exactly like any other copy the user makes and Passman never touches it
 * again.
 */
data class ClipboardExpiry(
    val enabled: Boolean,
    val duration: Duration,
) {
    companion object {
        /** On, at thirty seconds: long enough to switch apps and paste, short enough to matter. */
        val Default = ClipboardExpiry(enabled = true, duration = 30.seconds)
    }
}
