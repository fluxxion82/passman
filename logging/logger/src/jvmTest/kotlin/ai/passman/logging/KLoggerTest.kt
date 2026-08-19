package ai.passman.logging

import io.mockk.mockk
import io.mockk.verify
import org.junit.After
import org.junit.Before
import org.junit.Test

class KLoggerTest {

    class InnerClass {
        fun doLog() = KLogger.d { "msg" }
    }

    private lateinit var loggers: Collection<Logger>

    @After
    fun cleanUp() {
        KLogger.unregisterLoggers(loggers)
    }

    @Before
    fun registerLoggers() {
        loggers = listOf<Logger>(mockk(relaxed = true), mockk(relaxed = true)).also {
            KLogger.registerLoggers(it)
        }
    }

    @Test
    fun properTagIsGeneratedWhenLoggedFromTest() {
        KLogger.d { "msg" }
        loggers.forEach {
            verify { it.log(
                Logger.Priority.DEBUG,
                null,
                "KLoggerTest#properTagIsGeneratedWhenLoggedFromTest:31",
                "msg",
                null,
                null
            ) }
        }
    }

    @Test
    fun properTagIsGeneratedWhenLoggedFromClass() {
        SomeClass().doLog()
        loggers.forEach {
            verify { it.log(
                Logger.Priority.DEBUG,
                null,
                "SomeClass#doLog:76",
                "msg",
                null,
                null
            ) }
        }
    }

    @Test
    fun properTagIsGeneratedWhenLoggedFromInnerClass() {
        InnerClass().doLog()
        loggers.forEach {
            verify { it.log(
                Logger.Priority.DEBUG,
                null,
                "KLoggerTest\$InnerClass#doLog:12",
                "msg",
                null,
                null
            ) }
        }
    }
}

class SomeClass {
    fun doLog() = KLogger.d { "msg" }
}

// Layout warning: these tests assert the source line numbers that KLogger.InferTag
// derives from the call site — :12, :31 and :76 above. Adding, removing or reflowing
// any line before those call sites changes the generated tags and fails the tests.
// The slightly odd `verify { it.log(` bracing exists to keep the MockK migration
// line-for-line identical to the mockito version it replaced.
