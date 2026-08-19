package ai.passman.domain.intialization

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.initialization.AppInitializer
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import org.junit.Before

class InitializeApplicationTest {

    lateinit var contextFacade: CoroutinesContextFacade

    @Before
    fun setUp() {
        contextFacade = mockk {
            every { default } returns Dispatchers.Unconfined
        }
    }

//    @Test
//    fun `should execute all initializers`() {
//        val firstRun = AtomicInteger(0)
//        val first = ExecutableInitializer { firstRun.incrementAndGet() }
//        val secondRun = AtomicInteger(0)
//        val second = ExecutableInitializer { secondRun.incrementAndGet() }
//        val useCase = InitializeApplication(setOf(first, second), contextFacade)
//
//        runBlocking { useCase(Unit) }
//
//        assertThat(firstRun.get()).isEqualTo(1)
//        assertThat(secondRun.get()).isEqualTo(1)
//    }
//
//    @Test
//    fun `does not run on init`() {
//        val atomicInteger = AtomicInteger(0)
//        val first = ExecutableInitializer { atomicInteger.incrementAndGet() }
//
//        InitializeApplication(setOf(first), contextFacade)
//
//        assertThat(atomicInteger.get()).isEqualTo(0)
//    }
//
//    @Test
//    fun `runs tasks in parallel`() {
//        contextFacade.stub {
//            on { default } doReturn Dispatchers.Default
//        }
//        val countDownLatch = CountDownLatch(2)
//        val first = ExecutableInitializer {
//            countDownLatch.await()
//        }
//        val secondRun = AtomicInteger(0)
//        val second = ExecutableInitializer {
//            secondRun.incrementAndGet()
//            countDownLatch.countDown()
//        }
//        val third = ExecutableInitializer {
//            countDownLatch.countDown()
//        }
//        val useCase = InitializeApplication(setOf(first, second, third), contextFacade)
//
//        runBlocking { useCase(Unit) }
//
//        assertThat(secondRun.get()).isEqualTo(1)
//    }
}

private class ExecutableInitializer(private val action: suspend () -> Unit) : AppInitializer {
    override suspend fun initialize() = action()
}
