package ai.passman.domain.settings.repository

import ai.passman.domain.settings.model.SyncLogEntry

/**
 * Contract only — see `LocalSyncLogRepository` for the storage decision and the invariant that
 * keeps this log off the wire.
 */
interface SyncLogRepository {
    /**
     * Adds [entry], trimming to the newest 100 records if the log has grown past that. Trimming
     * happens here, on write, not on [recent] — a reader must never see more than the store
     * actually intends to keep.
     */
    suspend fun append(entry: SyncLogEntry)

    /** Every record this device has kept, newest first. */
    suspend fun recent(): List<SyncLogEntry>

    /** Drops every record. The user's own log, on their own device — theirs to clear. */
    suspend fun clear()
}
