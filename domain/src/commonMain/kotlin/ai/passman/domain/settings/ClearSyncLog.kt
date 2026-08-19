package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.repository.SyncLogRepository

/**
 * Drops this device's sync activity log. Not named in the storage design alongside
 * [RecordSyncOutcome] and [GetSyncLog], but the "Clear log" action the UI offers still needs a
 * use case of its own: view models depend on `domain`, never on data-layer repositories directly.
 */
class ClearSyncLog(
    private val repository: SyncLogRepository,
) : Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) = repository.clear()
}
