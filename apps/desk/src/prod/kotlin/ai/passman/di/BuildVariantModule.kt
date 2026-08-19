package ai.passman.di

import ai.passman.repo.DesktopProfile
import org.koin.dsl.module

/**
 * Production variant bindings. Compiled in only when the app is built with
 * `-Ppassman.variant=prod`, which packaging tasks require.
 *
 * No [ai.passman.logging.Logger] is registered on purpose. The file logger creates its output file
 * during construction, and even warning and error messages can contain account names, vault paths,
 * or provider text. With no registered logger, KLogger's lazy messages are never evaluated and no
 * log directory or console output is produced.
 */
val buildVariantModule = module {
    single { DesktopProfile.Prod }
}
