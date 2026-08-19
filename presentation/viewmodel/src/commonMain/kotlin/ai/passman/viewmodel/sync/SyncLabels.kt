package ai.passman.viewmodel.sync

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
