package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository

/**
 * Repoints a pairing at a new address — the working path for a paired device whose DHCP lease
 * moved it on the LAN. Only the address changes; the pinned keys stay untouched.
 */
class UpdateTrustedDeviceHost(
    private val repository: TrustedDevicesRepository,
) : Usecase<UpdateTrustedDeviceHost.Parameters, Unit> {
    data class Parameters(val name: String, val host: String)

    override suspend fun invoke(param: Parameters) {
        val trimmed = param.host.trim()
        if (trimmed.isEmpty()) return
        repository.updateHost(param.name, trimmed)
    }
}
