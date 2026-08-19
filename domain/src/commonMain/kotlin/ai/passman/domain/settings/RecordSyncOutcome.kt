package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import ai.passman.logging.KLogger
import kotlin.time.Clock
import kotlinx.coroutines.CancellationException

/**
 * Appends one terminal sync outcome to this device's sync activity log.
 *
 * The single seam every sync wrapper (`SyncPasswords`, `SyncPgpKeys`, `SyncKeystores`) calls
 * through, so "resolve the device name for a host" and "never let a logging failure escape into
 * the sync flow" are each written once rather than three times.
 *
 * [deviceName] is resolved here, from [host], the same way the existing `updateLastSync` call
 * does at the point a session succeeds: [TrustedDevicesRepository.getByHost]. A host with no
 * matching trusted device (paired since removed, or never truly paired) logs an empty name rather
 * than failing the recording — the row still has [host] to show.
 *
 * Recording must never fail a sync: whatever happens here — a lookup that throws, a store that
 * cannot be written — is logged and swallowed. The outcome the user sees on screen belongs to the
 * sync itself, not to the log of it. [CancellationException] is the one exception let through,
 * because it means the caller was cancelled, not that recording failed.
 */
class RecordSyncOutcome(
    private val syncLogRepository: SyncLogRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val clock: Clock = Clock.System,
) : Usecase<RecordSyncOutcome.Params, Unit> {

    data class Params(
        val artifact: String,
        val host: String,
        val outcome: String,
        val detail: String = "",
    )

    override suspend fun invoke(param: Params) {
        runCatching {
            val deviceName = trustedDevices.getByHost(param.host)?.name.orEmpty()
            syncLogRepository.append(
                SyncLogEntry(
                    at = clock.now().toEpochMilliseconds(),
                    artifact = param.artifact,
                    host = param.host,
                    deviceName = deviceName,
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
