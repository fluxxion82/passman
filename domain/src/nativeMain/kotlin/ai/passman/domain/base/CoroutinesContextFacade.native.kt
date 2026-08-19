package ai.passman.domain.base

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Runnable
import platform.darwin.dispatch_async
import platform.darwin.dispatch_get_main_queue
import platform.darwin.dispatch_queue_t

actual class DefaultContextFacade : CoroutinesContextFacade {
    override val io: CoroutineContext = NsQueueDispatcher(dispatch_get_main_queue())
    override val main: CoroutineContext = NsQueueDispatcher(dispatch_get_main_queue())
    override val default: CoroutineContext = NsQueueDispatcher(dispatch_get_main_queue())
    override val unconfined: CoroutineContext = NsQueueDispatcher(dispatch_get_main_queue())
    override val errorHandler: CoroutineContext = CoroutineExceptionHandler { _, error ->
        when (error.cause) {
            else -> throw error
        }
    }
}

actual fun defaultContextFacade(): CoroutinesContextFacade = DefaultContextFacade()

class NsQueueDispatcher(
    private val dispatchQueue: dispatch_queue_t,
) : CoroutineDispatcher() {
    override fun dispatch(context: CoroutineContext, block: Runnable) {
        dispatch_async(dispatchQueue) {
            block.run()
        }
    }
}
