package ai.passman.domain.base

import ai.passman.logging.KLogger
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers

actual class DefaultContextFacade : CoroutinesContextFacade {
    override val io: CoroutineContext = Dispatchers.IO
    override val main: CoroutineContext = Dispatchers.Main
    override val default: CoroutineContext = Dispatchers.Default
    override val unconfined: CoroutineContext = Dispatchers.Unconfined
    override val errorHandler: CoroutineContext = CoroutineExceptionHandler { _, error ->
        KLogger.e(error) { "coroutine exception: ${error.message}" }
        when (error.cause) {
            else -> throw error
        }
    }
}

actual fun defaultContextFacade(): CoroutinesContextFacade = DefaultContextFacade()
