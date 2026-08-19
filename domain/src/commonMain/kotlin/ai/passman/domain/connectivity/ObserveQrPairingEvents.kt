package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import kotlinx.coroutines.flow.SharedFlow

/**
 * What the pairing listener made of the pushes that arrived while a code was on screen.
 *
 * The flow is hot and has no replay: it reports pushes as they land, and a collector that was not
 * subscribed yet misses them. A screen coming back from a recreation therefore subscribes *and* asks
 * [GetArmedQrPairing] what it may have missed.
 */
class ObserveQrPairingEvents(
    private val qrPairingSession: QrPairingSession,
) : Usecase<Unit, SharedFlow<QrPairingEvent>> {
    override suspend fun invoke(param: Unit): SharedFlow<QrPairingEvent> = qrPairingSession.events
}
