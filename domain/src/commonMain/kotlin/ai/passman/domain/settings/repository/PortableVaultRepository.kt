package ai.passman.domain.settings.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.model.PortableVaultAccess

/** Explicit access to the recovery material for the currently logged-in profile. */
interface PortableVaultRepository {
    suspend fun getAccess(): Outcome<PortableVaultAccess>

    /** Explicitly re-protects a legacy recovery P12 with a 24-word BIP39 phrase. */
    suspend fun upgradeToBip39Phrase(): Outcome<PortableVaultAccess>
}
