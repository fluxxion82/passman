package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import kotlinx.coroutines.flow.Flow

class GetTrustedDevices(
    private val repository: TrustedDevicesRepository,
): Usecase<Unit, Flow<List<TrustedDevice>>> {
    override suspend fun invoke(param: Unit): Flow<List<TrustedDevice>> = repository.observeAll()
}
