package ai.passman.di

import ai.passman.di.config.FileLogger
import ai.passman.logging.Logger
import ai.passman.logging.jvm.JvmLogger
import ai.passman.repo.DesktopProfile
import org.koin.dsl.bind
import org.koin.dsl.module

/**
 * Debug variant bindings. Compiled in only when the app is built with `-Ppassman.variant=debug`
 * (the default); `src/prod` supplies the same declaration for release builds.
 *
 * Debug keeps both log sinks at full verbosity, and runs against the isolated debug data dir,
 * prefs node, and credential-storage key that [DesktopProfile.Debug] names.
 */
val buildVariantModule = module {
    single { DesktopProfile.Debug }

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
