package ai.passman.domain.initialization

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.Usecase
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

class InitializeApplication(
    private val initializers: Set<AppInitializer>,
    private val contextFacade: CoroutinesContextFacade
) : Usecase<Unit, Unit> {

    override suspend fun invoke(param: Unit) = coroutineScope {
        initializers.forEach {
            launch(contextFacade.default) { it.initialize() }
        }
    }
}
