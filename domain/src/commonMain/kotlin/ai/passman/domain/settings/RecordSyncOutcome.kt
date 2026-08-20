package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import ai.passman.logging.KLogger
import kotlin.time.Clock
import kotlinx.coroutines.CancellationException

/**
 * Appends one terminal sync outcome to this device's sync activity log.
 *
 * The single seam every sync wrapper (`SyncPasswords`, `SyncPgpKeys`, `SyncKeystores`) calls
 * through, so "never let a logging failure escape into the sync flow" is written once rather than
 * three times.
 *
 * [Params.deviceName] is *given*, not resolved. This use case used to look the name up from
 * [Params.host] via `TrustedDevicesRepository.getByHost`, which is a first-match lookup over an
 * address two pairings can legitimately share — so a log row could name a device the user never
 * synced with. The session already holds the [ai.passman.domain.connectivity.model.TrustedDevice]
 * the user chose and passes its name in, which is the only reading guaranteed to match the pairing
 * that was actually pinned and stamped. A caller with no device to name passes an empty string; the
 * row still has [Params.host] to show.
 *
 * Recording must never fail a sync: whatever happens here — a store that cannot be written — is
 * logged and swallowed. The outcome the user sees on screen belongs to the sync itself, not to the
 * log of it. [CancellationException] is the one exception let through, because it means the caller
 * was cancelled, not that recording failed.
 */
class RecordSyncOutcome(
    private val syncLogRepository: SyncLogRepository,
    private val clock: Clock = Clock.System,
) : Usecase<RecordSyncOutcome.Params, Unit> {

    data class Params(
        val artifact: String,
        val host: String,
        val deviceName: String,
        val outcome: String,
        val detail: String = "",
    )

    override suspend fun invoke(param: Params) {
        runCatching {
            syncLogRepository.append(
                SyncLogEntry(
                    at = clock.now().toEpochMilliseconds(),
                    artifact = param.artifact,
                    host = param.host,
                    deviceName = param.deviceName,
                    outcome = param.outcome,
                    detail = param.detail,
                ),
            )
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) {
                "failed to record sync outcome for ${param.artifact} (${param.outcome}); " +
                    "the sync itself already completed and is unaffected"
            }
        }
    }
}
