package ai.passman.di

import ai.passman.di.config.LoggingInitializer
import ai.passman.logging.Logger
import ai.passman.domain.initialization.AppInitializer
import org.koin.dsl.bind
import org.koin.dsl.module

/**
 * Collects whatever log sinks the active build variant registered. `src/debug` binds the console
 * and file loggers; `src/prod` binds none, so this initializer starts with an empty set and the
 * app produces no log output at all in a packaged build.
 */
val loggingModule = module {
    single { LoggingInitializer(loggers = getKoin().getAll<Logger>().toSet()) } bind AppInitializer::class
}
