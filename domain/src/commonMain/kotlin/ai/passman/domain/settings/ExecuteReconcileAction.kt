package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.repository.TransferRepository

class ExecuteReconcileAction(
    private val transferRepository: TransferRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
): Usecase<ReconcileAction, Outcome<Unit>> {
    override suspend fun invoke(param: ReconcileAction): Outcome<Unit> {
        val outcome = transferRepository.executeReconcileAction(param)
        if (outcome is Outcome.Success) {
            passwordEventPersistence.update(PasswordEvent.Updated)
        }
        return outcome
    }
}
