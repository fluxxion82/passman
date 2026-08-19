package ai.passman.domain.user

import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.invoke
import ai.passman.domain.initialization.AppInitializer
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.services.UserAwareService
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class UserInfoInitializer(
    private val getAppUser: GetAppUser,
    private val services: Set<UserAwareService>,
    private val scopeFacade: CoroutineScopeFacade
) : AppInitializer {

    override suspend fun initialize() {
        scopeFacade.globalScope.launch {
            getAppUser().collect {
                notifyAll(it)
            }
        }
    }

    private suspend fun notifyAll(user: AppUser) = coroutineScope {
        services.forEach { service ->
            launch {
                service.onUserChanged(user)
            }
        }
    }
}
