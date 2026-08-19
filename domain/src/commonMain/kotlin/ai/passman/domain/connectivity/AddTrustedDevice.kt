package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.repository.UserPreferences

/**
 * Stores a pairing that arrived with no ceremony behind it.
 *
 * There is no earlier point at which this device's owner was fixed — no exchange was begun, nothing
 * was stamped — so the account signed in at entry is the only claim that can be made, and it is
 * made here rather than left to the store to guess: the store compares it under its write lock, so
 * an account switch that lands during the write is still refused.
 *
 * @see TrustedDevicesRepository.add — the result is whether the pairing was actually stored.
 */
class AddTrustedDevice(
    private val repository: TrustedDevicesRepository,
    private val userPreferences: UserPreferences,
): Usecase<TrustedDevice, Boolean> {
    override suspend fun invoke(param: TrustedDevice): Boolean =
        repository.add(param, PairingOwner.current(userPreferences))
}
