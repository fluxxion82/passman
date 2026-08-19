package ai.passman.pgp

import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import java.net.ConnectException
import java.net.UnknownHostException
import javax.inject.Inject
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.*

internal class TestScopeFacade(job: Job, dispatcher: CoroutineDispatcher = Dispatchers.Unconfined) :
    CoroutineScopeFacade {
    override val globalScope: CoroutineScope = TestScope(job + dispatcher)
    override var transferScope: CoroutineScope = TestScope(job + dispatcher)
}

internal class TestContextFacade @Inject constructor() : CoroutinesContextFacade {
    override val io = Dispatchers.IO
    override val main = Dispatchers.Main
    override val default = Dispatchers.Default
    override val unconfined: CoroutineContext = Dispatchers.Unconfined
    override val errorHandler = CoroutineExceptionHandler { _, error ->
        when (error.cause) {
            is UnknownHostException, is ConnectException -> {
            }
            else -> throw error
        }
    }
}

private class TestScope(override val coroutineContext: CoroutineContext) : CoroutineScope
