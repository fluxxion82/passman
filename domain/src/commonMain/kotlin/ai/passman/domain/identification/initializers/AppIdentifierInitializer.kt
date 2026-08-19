package ai.passman.domain.identification.initializers

import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.identification.repositories.AppIdentifyingRepository
import ai.passman.domain.identification.services.AppIdentifyingService
import ai.passman.domain.initialization.AppInitializer
import kotlinx.coroutines.launch

internal class AppIdentifierInitializer(
    private val repository: AppIdentifyingRepository,
    private val service: AppIdentifyingService,
    private val scopeFacade: CoroutineScopeFacade
) : AppInitializer {

    override suspend fun initialize() {
        scopeFacade.globalScope.launch {
            runCatching {
                service.clearIdentifier()
                repository.setIdentifier(null)
                val token = service.getIdentifier()
                repository.setIdentifier(token)
            }
        }
    }
}
