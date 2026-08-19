package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.repository.TransferRepository

class GetIpAddress(
    private val transferRepository: TransferRepository,
): Usecase<Unit, String> {
    override suspend fun invoke(param: Unit): String {
        return transferRepository.getIpAddress()
    }
}
