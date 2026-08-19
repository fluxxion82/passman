package ai.passman.domain.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.repository.PortableVaultRepository

class GetPortableVaultAccess(private val repository: PortableVaultRepository) {
    suspend operator fun invoke(): Outcome<PortableVaultAccess> = repository.getAccess()
}
