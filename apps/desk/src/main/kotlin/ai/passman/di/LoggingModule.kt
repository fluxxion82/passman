package ai.passman.di

import ai.passman.di.config.FileLogger
import ai.passman.di.config.LoggingInitializer
import ai.passman.repo.DesktopProfile
import ai.passman.logging.Logger
import ai.passman.logging.jvm.JvmLogger
import ai.passman.domain.initialization.AppInitializer
import org.koin.dsl.bind
import org.koin.dsl.module

/**
 * Logging differs by runtime profile, selected via the `passman.profile` system property.
 * `:apps:desk:run` sets it to debug; packaged distributions do not, so they run as prod.
 *
 * Debug keeps both sinks at full verbosity. Prod registers no sink: the file logger creates
 * its output file during construction, and even warning/error messages can contain account
 * names, vault paths, or provider text. With no registered logger, KLogger's lazy messages
 * are not evaluated and no log directory or console output is produced.
 */
val loggingModule = module {
    if (DesktopProfile.isDebug) {
        single { JvmLogger } bind Logger::class
        single {
            FileLogger(
                platform = get(),
                appInformation = get(),
                deviceInfo = get(),
                coroutineScopeFacade = get(),
            )
        } bind Logger::class
    }
    single { LoggingInitializer(loggers = getKoin().getAll<Logger>().toSet()) } bind AppInitializer::class
}
