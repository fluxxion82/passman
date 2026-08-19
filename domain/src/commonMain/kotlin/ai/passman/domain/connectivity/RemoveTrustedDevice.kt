package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository

class RemoveTrustedDevice(
    private val repository: TrustedDevicesRepository,
): Usecase<String, Unit> {
    override suspend fun invoke(param: String) {
        repository.remove(param)
    }
}
