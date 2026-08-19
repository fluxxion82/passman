package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository

/**
 * The paired devices a sync can target, most recently synced first so the top row is the
 * device the user almost certainly wants. Never-synced pairings sort after all synced ones.
 */
class GetSyncTargets(
    private val repository: TrustedDevicesRepository,
) : Usecase<Unit, List<TrustedDevice>> {
    override suspend fun invoke(param: Unit): List<TrustedDevice> =
        repository.getAll().sortedWith(
            compareByDescending<TrustedDevice> { it.lastSyncedAt }
                .thenBy { it.name.lowercase() },
        )
}
