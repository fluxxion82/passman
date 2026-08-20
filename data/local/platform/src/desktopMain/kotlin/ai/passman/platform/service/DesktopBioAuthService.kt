package ai.passman.platform.service

import ai.passman.domain.user.models.BiometricAvailability

/**
 * Permanently unavailable, and honest about which kind of unavailable.
 *
 * [BiometricAvailability.NoHardware] rather than `Unavailable`, because the two lead the UI
 * somewhere different: `Unavailable` means "try again later" and would leave a settings row that
 * can never be switched on, whereas `NoHardware` hides the row. Desktop has no keystore this
 * design could hang a per-operation biometric key off — the JVM has no equivalent of
 * `setUserAuthenticationRequired` — so there is nothing to try later.
 */
internal class DesktopBioAuthService : BioAuthService {
    override suspend fun canAuthenticate(): BiometricAvailability = BiometricAvailability.NoHardware

    override suspend fun enroll(alias: String, secret: ByteArray): BioAuthService.EnrollOutcome =
        BioAuthService.EnrollOutcome.Failed(BioAuthFailure.Unavailable)

    override suspend fun unlock(alias: String, wrapped: WrappedSecret): BioAuthService.UnlockOutcome =
        BioAuthService.UnlockOutcome.Failed(BioAuthFailure.Unavailable)

    override suspend fun discard(alias: String) = Unit
}
