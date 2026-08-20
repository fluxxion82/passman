package ai.passman.viewmodel.sync

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import kotlin.time.Clock
import kotlinx.coroutines.delay

private const val MINUTE_MS = 60_000L
private const val HOUR_MS = 60 * MINUTE_MS
private const val DAY_MS = 24 * HOUR_MS

/** "Never synced", "Just now", "12m ago", "3h ago", "5d ago". */
fun lastSyncedLabel(lastSyncedAt: Long, nowMs: Long): String {
    if (lastSyncedAt <= 0L) return "Never synced"
    val elapsed = nowMs - lastSyncedAt
    return when {
        elapsed < MINUTE_MS -> "Just now"
        elapsed < HOUR_MS -> "${elapsed / MINUTE_MS}m ago"
        elapsed < DAY_MS -> "${elapsed / HOUR_MS}h ago"
        else -> "${elapsed / DAY_MS}d ago"
    }
}

/**
 * A "now" that keeps moving while it is on screen, for the relative labels [lastSyncedLabel]
 * renders.
 *
 * `Clock.System.now()` read straight into a composable body is sampled once per composition, so a
 * label computed from it freezes at whatever it said when the dialog opened — a sync chooser left
 * up for five minutes keeps claiming "Just now". Reading the clock from state that a ticker
 * republishes is what makes the label a function of real elapsed time again.
 *
 * [periodMs] defaults to 30s rather than a minute on purpose. [lastSyncedLabel]'s finest step *is*
 * one minute, so a tick that also ran once a minute would be in an arbitrary phase against the
 * flip it exists to catch — up to a full minute late, the entire width of the step. Sampling at
 * half the step bounds the staleness to half of it instead. It costs one wakeup every 30s for as
 * long as the dialog is open, and the effect is cancelled with the composable, so nothing ticks
 * behind a closed chooser.
 *
 * Kept here, next to the label it feeds, rather than inside `SyncTargetDialog`: that dialog takes
 * `lastSyncedLabel` as a callback precisely so `presentation/design` never reads a clock, and
 * moving the ticker in there would undo that on the design module's behalf.
 */
@Composable
fun rememberNowMs(periodMs: Long = 30_000L): Long {
    var nowMs by remember { mutableLongStateOf(Clock.System.now().toEpochMilliseconds()) }
    LaunchedEffect(periodMs) {
        while (true) {
            delay(periodMs)
            nowMs = Clock.System.now().toEpochMilliseconds()
        }
    }
    return nowMs
}
