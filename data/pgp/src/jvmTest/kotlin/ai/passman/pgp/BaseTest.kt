package ai.passman.pgp

import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlinx.coroutines.*
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Before

abstract class BaseTest {
//    @get:Rule
//    val instantExecutorRule = InstantTaskExecutorRule()

    @InternalCoroutinesApi
    @Before
    fun setUpMainDispatcher() {
        Dispatchers.setMain(TestUiContext)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }
}

@InternalCoroutinesApi
object TestUiContext : CoroutineDispatcher(), Delay {
    override fun scheduleResumeAfterDelay(timeMillis: Long, continuation: CancellableContinuation<Unit>) {
        continuation.resume(Unit)
    }

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        block.run()
    }
}
