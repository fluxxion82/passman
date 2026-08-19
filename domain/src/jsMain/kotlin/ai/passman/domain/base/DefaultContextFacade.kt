package ai.passman.domain.base

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers

actual class DefaultContextFacade : CoroutinesContextFacade {
    override val io: CoroutineContext = Dispatchers.Default
    override val main: CoroutineContext = Dispatchers.Main
    override val default: CoroutineContext = Dispatchers.Default
    override val unconfined: CoroutineContext = Dispatchers.Unconfined
    override val errorHandler: CoroutineContext = CoroutineExceptionHandler { _, error ->
        when (error.cause) {
            else -> throw error
        }
    }
}

actual fun defaultContextFacade(): CoroutinesContextFacade = DefaultContextFacade()
