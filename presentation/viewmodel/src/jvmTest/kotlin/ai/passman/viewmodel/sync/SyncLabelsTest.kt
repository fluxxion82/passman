package ai.passman.viewmodel.sync

import kotlin.test.Test
import kotlin.test.assertEquals

class SyncLabelsTest {
    private val now = 1_000_000_000_000L

    @Test
    fun `zero sentinel means never synced`() {
        assertEquals("Never synced", lastSyncedLabel(lastSyncedAt = 0L, nowMs = now))
    }

    @Test
    fun `negative timestamp also means never synced`() {
        assertEquals("Never synced", lastSyncedLabel(lastSyncedAt = -5L, nowMs = now))
    }

    @Test
    fun `under a minute is just now`() {
        assertEquals("Just now", lastSyncedLabel(lastSyncedAt = now - 59_999L, nowMs = now))
    }

    @Test
    fun `minutes bucket`() {
        assertEquals("12m ago", lastSyncedLabel(lastSyncedAt = now - 12 * 60_000L, nowMs = now))
        assertEquals("1m ago", lastSyncedLabel(lastSyncedAt = now - 60_000L, nowMs = now))
        assertEquals("59m ago", lastSyncedLabel(lastSyncedAt = now - 59 * 60_000L - 59_999L, nowMs = now))
    }

    @Test
    fun `hours bucket`() {
        assertEquals("3h ago", lastSyncedLabel(lastSyncedAt = now - 3 * 3_600_000L, nowMs = now))
        assertEquals("1h ago", lastSyncedLabel(lastSyncedAt = now - 3_600_000L, nowMs = now))
        assertEquals("23h ago", lastSyncedLabel(lastSyncedAt = now - 24 * 3_600_000L + 1, nowMs = now))
    }

    @Test
    fun `days bucket`() {
        assertEquals("5d ago", lastSyncedLabel(lastSyncedAt = now - 5 * 86_400_000L, nowMs = now))
        assertEquals("1d ago", lastSyncedLabel(lastSyncedAt = now - 86_400_000L, nowMs = now))
    }

    @Test
    fun `future timestamp from clock skew reads as just now`() {
        assertEquals("Just now", lastSyncedLabel(lastSyncedAt = now + 90_000L, nowMs = now))
    }
}
