package ai.passman.logging

import kotlin.test.Test
import kotlin.test.assertEquals

class MinimumPriorityLoggerTest {

    private class RecordingLogger : Logger {
        val recorded = mutableListOf<Logger.Priority>()

        @Suppress("LongParameterList")
        override fun log(
            priority: Logger.Priority,
            explicitTag: String?,
            inferredTag: String,
            message: String?,
            throwable: Throwable?,
            properties: Map<String, String>?,
        ) {
            recorded += priority
        }
    }

    private fun MinimumPriorityLogger.record(priority: Logger.Priority) =
        log(priority, null, "tag", "message", null, null)

    @Test
    fun dropsEverythingBelowTheThreshold() {
        val delegate = RecordingLogger()
        val logger = MinimumPriorityLogger(delegate, Logger.Priority.WARNING)

        Logger.Priority.entries.forEach { logger.record(it) }

        assertEquals(
            listOf(Logger.Priority.WARNING, Logger.Priority.ERROR, Logger.Priority.WTF),
            delegate.recorded,
        )
    }

    /** The case that motivated this: debug output records vault paths and user names. */
    @Test
    fun debugAndVerboseNeverReachTheDelegate() {
        val delegate = RecordingLogger()
        val logger = MinimumPriorityLogger(delegate, Logger.Priority.WARNING)

        logger.record(Logger.Priority.VERBOSE)
        logger.record(Logger.Priority.DEBUG)
        logger.record(Logger.Priority.INFO)

        assertEquals(emptyList(), delegate.recorded)
    }

    @Test
    fun defaultThresholdIsWarning() {
        val delegate = RecordingLogger()
        val logger = MinimumPriorityLogger(delegate)

        logger.record(Logger.Priority.INFO)
        logger.record(Logger.Priority.WARNING)

        assertEquals(listOf(Logger.Priority.WARNING), delegate.recorded)
    }

    @Test
    fun passesEverythingThroughWhenThresholdIsLowest() {
        val delegate = RecordingLogger()
        val logger = MinimumPriorityLogger(delegate, Logger.Priority.VERBOSE)

        Logger.Priority.entries.forEach { logger.record(it) }

        assertEquals(Logger.Priority.entries.toList(), delegate.recorded)
    }
}
