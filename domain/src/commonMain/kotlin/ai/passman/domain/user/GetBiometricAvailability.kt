package ai.passman.domain.user

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.models.BiometricAvailability
import ai.passman.domain.user.repository.BiometricUnlockRepository

/**
 * What this device can do about biometrics, with no account in the picture.
 *
 * The signup form's question, and the reason it cannot use [GetBiometricUnlockState]: that use case
 * answers about an account, and signup is drawing a checkbox for a name that does not exist yet. It
 * deliberately refuses a blank username rather than asking the platform about "", so there is
 * nothing sensible for signup to pass it.
 *
 * `Available` is the only answer that draws the checkbox. `NotEnrolled` means a sensor with no
 * fingerprint registered, and a signup form is the wrong place to send somebody into system
 * settings; `NoHardware` is the desktop answer and hides it outright.
 */
class GetBiometricAvailability(
    private val repository: BiometricUnlockRepository,
) : Usecase<Unit, BiometricAvailability> {
    override suspend fun invoke(param: Unit): BiometricAvailability = repository.biometricAvailability()
}
