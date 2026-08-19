package ai.passman.android.di

import ai.passman.android.di.config.LoggingInitializer
import ai.passman.logging.Logger
import ai.passman.domain.initialization.AppInitializer
import org.koin.dsl.bind
import org.koin.dsl.module

val loggingModule = module {
    single { LoggingInitializer(loggers = getKoin().getAll<Logger>().toSet()) } bind AppInitializer::class
}
