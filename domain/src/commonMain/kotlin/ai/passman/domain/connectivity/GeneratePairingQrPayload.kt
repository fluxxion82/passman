package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.repository.TransferRepository
import ai.passman.domain.user.repository.UserPreferences

/**
 * Build the code this device puts on screen, and arm the single-use nonce that gives it its meaning.
 *
 * The code is a commitment, not a secret: an address to fetch this device's identity bundle from, a
 * digest of that bundle so the scanner can tell it fetched the right one, and a fresh random nonce.
 * Only the nonce matters cryptographically — a peer that can key an HMAC on it saw this screen, and
 * that is what [QrPairingSession] trades the manual safety-number compare for.
 *
 * The nonce is drawn per call and registered last, after every step that can fail has already
 * succeeded. A nonce armed beside a returned error would leave the pairing listener accepting pushes
 * against a code the user was never shown — the session would be armed with nobody watching.
 *
 * Concurrent invocations both arm and the last one to register wins, retiring the nonce before it.
 * Keeping a showing to one call at a time is the caller's job; the ViewModel's ceremony job is where
 * that guard lives.
 */
class GeneratePairingQrPayload(
    private val fingerprintService: FingerprintService,
    private val qrPairingSession: QrPairingSession,
    private val userPreferences: UserPreferences,
    private val transferRepository: TransferRepository,
) : Usecase<Unit, Outcome<PairingQrPayload>> {
    override suspend fun invoke(param: Unit): Outcome<PairingQrPayload> {
        // First statement on purpose: the nonce must be stamped with the account that asked for the
        // code, so the account is sampled before anything below suspends. The address lookup and the
        // identity fetch both do, and a sign-in that lands while either is in flight would otherwise
        // stamp whoever the user had become — letting that account confirm a ceremony it never began.
        val owner = PairingOwner.current(userPreferences)
        val host = transferRepository.getIpAddress()
        if (host.isBlank()) {
            return Outcome.Error(
                "no network address available",
                TransferFailure.GeneralTransferFailure,
            )
        }
        val own = when (val result = fingerprintService.getOwnDeviceIdentityBundle()) {
            is Outcome.Success -> result.value
            is Outcome.Error -> return result
        }
        // Both computed outside the try so the catch below has exactly one statement under it and
        // only one plausible cause to name.
        val digest = own.digest(fingerprintService)
        val nonce = fingerprintService.randomBytes(NONCE_BYTES)
        val payload = try {
            PairingQrPayload(
                host = host,
                port = PairingQrPayload.DEFAULT_PAIRING_PORT,
                digest = digest,
                nonce = nonce,
            )
        } catch (_: IllegalArgumentException) {
            // The address came from a network interface, not from this code: a link-local IPv6
            // literal arrives with a `%zone` suffix the payload's host allowlist refuses. Callers
            // asked for an Outcome, so a platform answer we cannot put in a code is one of them.
            return Outcome.Error(
                "this device's network address cannot be put in a pairing code",
                TransferFailure.GeneralTransferFailure,
            )
        }
        qrPairingSession.register(nonce, owner)
        return Outcome.Success(payload)
    }

    private companion object {
        /** Matches the nonce width [PairingQrPayload] requires; 256 bits of HMAC key. */
        const val NONCE_BYTES = 32
    }
}
