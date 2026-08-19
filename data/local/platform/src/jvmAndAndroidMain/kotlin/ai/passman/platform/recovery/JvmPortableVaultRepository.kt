package ai.passman.platform.recovery

import ai.passman.cache.di.passmanSessionScope
import ai.passman.crypto.vault.VaultSession
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.repository.PortableVaultRepository
import ai.passman.domain.settings.exception.PortableVaultFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import org.koin.core.qualifier.named

class JvmPortableVaultRepository(
    private val userPreferences: UserPreferences,
    private val recovery: JvmPortableVaultRecovery,
) : PortableVaultRepository {
    override suspend fun getAccess(): Outcome<PortableVaultAccess> = runCatching {
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as? AppUser.LoggedIn
                ?: return@passmanSessionScope Outcome.Error("sign in before viewing portable vault access", PortableVaultFailure())
            val sessionKey = scope.get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()
            Outcome.Success(recovery.access(user.userName, sessionKey))
        } ?: Outcome.Error("no active password session", PortableVaultFailure())
    }.getOrElse { Outcome.Error("portable vault access failed", PortableVaultFailure()) }

    override suspend fun upgradeToBip39Phrase(): Outcome<PortableVaultAccess> = runCatching {
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as? AppUser.LoggedIn
                ?: return@passmanSessionScope Outcome.Error("sign in before upgrading portable vault access", PortableVaultFailure())
            val sessionKey = scope.get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()
            Outcome.Success(recovery.upgrade(user.userName, sessionKey))
        } ?: Outcome.Error("no active password session", PortableVaultFailure())
    }.getOrElse { Outcome.Error("portable vault recovery upgrade failed", PortableVaultFailure()) }
}
