package ai.passman.iosdi

import ai.passman.domain.di.domainModule
import org.koin.core.KoinApplication
import org.koin.core.context.startKoin
import org.koin.core.module.Module

/**
 * iOS entry point for Koin initialization.
 *
 * Swift code calls this from `iOSApp.swift` (typically inside the `init { }` block of the
 * `@main App` struct):
 *
 * ```swift
 * KoinIosKt.doInitKoinIos(extra: nil)
 * ```
 *
 * The `extra` parameter lets the iOS app contribute platform-specific bindings (logger
 * adapter, notification handler, etc.) without modifying shared code.
 *
 * NOTE: Repository bindings for `PgpRepository`, `KeystoreRepository`, `UserRepository`,
 * `PasswordRepository`, etc. are NOT loaded here. Those iOS-side stubs (or real
 * implementations once ObjectivePGP cinterop lands for PGP, Apple Keychain Services for
 * Keystore, etc.) belong in a future `iosModule` parameter passed through `extra`.
 */
fun initKoinIos(extra: Module? = null): KoinApplication = startKoin {
    modules(
        buildList {
            add(domainModule)
            // add(viewModelModule)
            extra?.let(::add)
        },
    )
}
