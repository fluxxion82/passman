package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.repository.TransferRepository

class StartPairingServer(
    val service: TransferRepository,
): Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) {
        service.startPairingServer()
    }
}
