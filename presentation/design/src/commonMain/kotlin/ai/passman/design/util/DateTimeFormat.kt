package ai.passman.design.util

import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/**
 * The one place a stored epoch-millisecond timestamp becomes text.
 *
 * Before this file every screen open-coded
 * `Instant.fromEpochMilliseconds(x).toLocalDateTime(TimeZone.currentSystemDefault())` and then picked
 * its own layout, so the app showed `2026-08-19` in one list and `19/8/2026 9:04` in another, with
 * zero-padding applied to minutes but not hours. New timestamp surfaces call these instead.
 *
 * ## Why ISO order and 24-hour time rather than something friendlier
 *
 * Compose Multiplatform's common source set has no locale-aware date formatter — `kotlinx.datetime`
 * deliberately stops at the calendar arithmetic and leaves presentation to the platform, so anything
 * "local-looking" here would be a hand-rolled guess at the user's conventions that is wrong for most
 * of the world. `2026-08-19 09:04` is unambiguous everywhere and sorts the way it reads. When a
 * platform-aware formatter is worth the expect/actual, it goes behind these two functions and every
 * call site inherits it.
 *
 * The zone is the device's current one, resolved per call rather than cached, so a timestamp
 * rendered either side of a travel-induced zone change is right both times.
 *
 * Note the two `formatInstant` copies in `presentation/viewmodel` (PgpAddKeyViewModel,
 * PgpAddSubKeyViewModel) are NOT covered by this: `viewmodel` does not depend on `design`, and
 * formatting in a view model is the thing to remove rather than to share. Left alone deliberately.
 */

/** Rendered for a timestamp that was never set. Callers that prefer their own wording pass their own. */
const val NO_TIMESTAMP = "—"

/** `2026-08-19`. For a list column where the time of day is noise. */
fun formatDate(timestampMs: Long, absent: String = NO_TIMESTAMP): String {
    if (timestampMs <= 0L) return absent
    return Instant.fromEpochMilliseconds(timestampMs)
        .toLocalDateTime(TimeZone.currentSystemDefault())
        .date
        .toString()
}

/** `2026-08-19 09:04`. For history and audit surfaces, where the time of day is the point. */
fun formatDateTime(timestampMs: Long, absent: String = NO_TIMESTAMP): String {
    if (timestampMs <= 0L) return absent
    val local = Instant.fromEpochMilliseconds(timestampMs).toLocalDateTime(TimeZone.currentSystemDefault())
    val hour = local.hour.toString().padStart(2, '0')
    val minute = local.minute.toString().padStart(2, '0')
    return "${local.date} $hour:$minute"
}
