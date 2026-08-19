package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository

/** This device's sync activity log, newest first. */
class GetSyncLog(
    private val repository: SyncLogRepository,
) : Usecase<Unit, List<SyncLogEntry>> {
    override suspend fun invoke(param: Unit): List<SyncLogEntry> = repository.recent()
}
