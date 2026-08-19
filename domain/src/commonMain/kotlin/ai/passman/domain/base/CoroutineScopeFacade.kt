package ai.passman.domain.base

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob

interface CoroutineScopeFacade {
    val globalScope: CoroutineScope
    var transferScope: CoroutineScope
}

class DefaultScopeFacade(
    contextFacade: CoroutinesContextFacade
) : CoroutineScopeFacade {
    val job = SupervisorJob()
    override val globalScope: CoroutineScope = CoroutineScope(contextFacade.default + job)
    override var transferScope: CoroutineScope = CoroutineScope(contextFacade.default + SupervisorJob())
}
