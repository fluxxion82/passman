//package ai.passman.domain.base
//
//import kotlinx.coroutines.CoroutineDispatcher
//import kotlinx.coroutines.CoroutineExceptionHandler
//import kotlinx.coroutines.Runnable
//import platform.darwin.dispatch_async
//import platform.darwin.dispatch_get_main_queue
//import platform.darwin.dispatch_queue_t
//import kotlin.coroutines.CoroutineContext
//
//actual class DefaultContextFacade : CoroutinesContextFacade {
//    override val io = NsQueueDispatcher(dispatch_get_main_queue())
//    override val main = NsQueueDispatcher(dispatch_get_main_queue())
//    override val default = NsQueueDispatcher(dispatch_get_main_queue())
//    override val unconfined = NsQueueDispatcher(dispatch_get_main_queue())
//    override val errorHandler = CoroutineExceptionHandler { _, error ->
//        when (error.cause) {
//            else -> throw error
//        }
//    }
//}
//
//class NsQueueDispatcher(
//    private val dispatchQueue: dispatch_queue_t,
//) : CoroutineDispatcher() {
//    override fun dispatch(context: CoroutineContext, block: Runnable) {
//        dispatch_async(dispatchQueue) {
//            block.run()
//        }
//    }
//}
