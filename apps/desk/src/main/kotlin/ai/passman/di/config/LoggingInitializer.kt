package ai.passman.di.config

import ai.passman.logging.KLogger
import ai.passman.logging.Logger
import ai.passman.domain.initialization.AppInitializer

internal class LoggingInitializer(
    private val loggers: Set<@JvmSuppressWildcards Logger>
) : AppInitializer {

    override suspend fun initialize() {
        KLogger.registerLoggers(loggers)
    }
}
