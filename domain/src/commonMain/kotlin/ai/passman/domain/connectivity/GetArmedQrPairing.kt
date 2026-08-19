package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.user.repository.UserPreferences

/**
 * The QR-verified exchange already waiting for a confirmation, if there is one.
 *
 * [ObserveQrPairingEvents] carries no replay, so a push that lands while the screen is being
 * recreated is announced to nobody. Asking this on the way in recovers exactly that case: the
 * pending state outlives the screen, and an exchange stamped [PendingPairing.verifiedViaQr] is one a
 * possession proof already bound to both identities.
 *
 * A manual exchange is deliberately not reported. It is a perfectly live pairing, but the screen
 * would have to be told to skip the safety-number compare for it, and nothing has earned that here.
 * [PendingPairingState.active] applies the rest of the rules: expired or begun under a different
 * sign-in is the same answer as nothing armed at all.
 */
class GetArmedQrPairing(
    private val pendingPairingState: PendingPairingState,
    private val userPreferences: UserPreferences,
) : Usecase<Unit, PendingPairing?> {
    override suspend fun invoke(param: Unit): PendingPairing? =
        pendingPairingState.active(PairingOwner.current(userPreferences))?.takeIf { it.verifiedViaQr }
}
