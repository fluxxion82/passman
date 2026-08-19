package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase

/**
 * Discard an unconfirmed pairing without persisting anything.
 *
 * Task 10's Trusted Devices screen must invoke this during screen teardown as well as when the user
 * explicitly cancels, so its plaintext bootstrap state cannot outlive the ceremony.
 *
 * That state is two halves and both go: the pending exchange, and the QR nonce the screen armed. A
 * nonce left registered after the code came off screen would keep accepting pushes against a QR
 * nobody can see any more — the one thing [QrPairingSession] exists to refuse.
 */
class CancelDevicePairing(
    private val pendingPairingState: PendingPairingState,
    private val qrPairingSession: QrPairingSession,
) : Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) {
        pendingPairingState.clear()
        qrPairingSession.clear()
    }
}
