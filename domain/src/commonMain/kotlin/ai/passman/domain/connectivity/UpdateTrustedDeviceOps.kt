package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository

class UpdateTrustedDeviceOps(
    private val repository: TrustedDevicesRepository,
): Usecase<UpdateTrustedDeviceOps.Params, Unit> {
    data class Params(val name: String, val allowedOps: Set<String>)

    override suspend fun invoke(param: Params) {
        repository.updateAllowedOps(param.name, param.allowedOps)
    }
}
