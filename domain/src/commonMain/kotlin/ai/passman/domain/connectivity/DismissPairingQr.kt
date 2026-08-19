package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase

/**
 * Take the pairing code off screen: the nonce behind it stops being accepted, and nothing else moves.
 *
 * Deliberately narrower than [CancelDevicePairing]. Closing the code is how the user gets to the
 * confirm card an inbound push just raised underneath it, so an exchange this session already
 * verified must survive — clearing the pending state here would throw away the pairing the user
 * closed the dialog to complete. Abandoning the whole ceremony is the other use-case's job.
 */
class DismissPairingQr(
    private val qrPairingSession: QrPairingSession,
) : Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) {
        qrPairingSession.clear()
    }
}
