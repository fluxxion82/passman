package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.repository.PasswordRepository

class TransferFile(
    private val passwordRepository: PasswordRepository,
): Usecase<String, Outcome<Unit>> {
    override suspend fun invoke(param: String): Outcome<Unit> {
        return passwordRepository.transferPasswordDatabase(param)
    }
}
