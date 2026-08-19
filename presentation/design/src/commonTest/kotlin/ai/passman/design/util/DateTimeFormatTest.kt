package ai.passman.design.util

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.datetime.LocalDateTime
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toInstant

/**
 * `formatDate`/`formatDateTime` resolve `TimeZone.currentSystemDefault()` per call, so this suite
 * cannot hardcode an expected string for a fixed epoch without pinning to whatever zone the machine
 * running the test happens to be in. Instead each known instant is built by converting a specific
 * *local* wall-clock reading to an epoch in that same zone and back, so the assertions stay exact —
 * including zero-padding a single-digit hour and minute, the specific defect these functions
 * replaced (see `DateTimeFormat.kt`'s KDoc) — while staying portable across whatever zone CI or a
 * developer's machine is in.
 *
 * July 15th is picked to sidestep the daylight-saving transition windows for both hemispheres
 * (roughly Feb-Apr and Sep-Nov), so no zone's local-to-instant conversion below lands on an
 * ambiguous or nonexistent wall-clock reading.
 */
class DateTimeFormatTest {

    private val zone = TimeZone.currentSystemDefault()
    private val knownLocal = LocalDateTime(2024, 7, 15, 9, 4, 0)
    private val knownEpochMs = knownLocal.toInstant(zone).toEpochMilliseconds()

    @Test
    fun `formatDate renders the ISO date with no time of day`() {
        assertEquals("2024-07-15", formatDate(knownEpochMs))
    }

    @Test
    fun `formatDateTime renders the date and a zero-padded 24-hour time`() {
        assertEquals("2024-07-15 09:04", formatDateTime(knownEpochMs))
    }

    @Test
    fun `formatDate returns the absent marker for a never-set timestamp`() {
        assertEquals(NO_TIMESTAMP, formatDate(0L))
    }

    @Test
    fun `formatDateTime returns the absent marker for a never-set timestamp`() {
        assertEquals(NO_TIMESTAMP, formatDateTime(0L))
    }
}
