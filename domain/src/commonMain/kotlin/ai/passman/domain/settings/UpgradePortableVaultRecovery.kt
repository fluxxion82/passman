package ai.passman.domain.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.repository.PortableVaultRepository

/** A deliberate opt-in upgrade; it is never called while merely opening Settings. */
class UpgradePortableVaultRecovery(private val repository: PortableVaultRepository) {
    suspend operator fun invoke(): Outcome<PortableVaultAccess> = repository.upgradeToBip39Phrase()
}
