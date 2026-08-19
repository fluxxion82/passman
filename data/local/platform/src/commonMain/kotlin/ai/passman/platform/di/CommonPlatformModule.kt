package ai.passman.platform.di

import ai.passman.platform.prefs.impl.LocalClipboardPreferences
import ai.passman.platform.prefs.impl.LocalCryptoPreferences
import ai.passman.platform.prefs.impl.LocalKeystorePreferences
import ai.passman.platform.prefs.impl.LocalPgpPreferences
import ai.passman.platform.prefs.impl.LocalTrustedDevicesRepository
import ai.passman.platform.prefs.impl.LocalUserPreferences
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.crypto.repository.CryptoPreferences
import ai.passman.domain.keystore.repository.KeystorePreferences
import ai.passman.domain.pgp.repository.PgpPreferences
import ai.passman.domain.user.repository.UserPreferences
import org.koin.dsl.module

val commonPlatformModule = module {
    single<UserPreferences> {
        LocalUserPreferences(encryptedFactory = get(), coroutinesContextFacade = get())
    }
    single<CryptoPreferences> {
        LocalCryptoPreferences(encryptedFactory = get(), coroutinesContextFacade = get())
    }
    // Bound as the concrete type, not as ClipboardPreferences: on JVM and Android the interface
    // resolves to a decorator that wraps this one, and that decorator has to be able to ask for
    // the store it wraps without asking for itself. Each platform module binds the interface.
    single {
        LocalClipboardPreferences(encryptedFactory = get(), coroutinesContextFacade = get())
    }
    single<KeystorePreferences> { LocalKeystorePreferences(encryptedFactory = get()) }
    single<PgpPreferences> { LocalPgpPreferences(encryptedFactory = get()) }
    single<TrustedDevicesRepository> {
        LocalTrustedDevicesRepository(
            encryptedFactory = get(),
            userPreferences = get(),
            userEvents = get(),
            coroutinesContextFacade = get(),
        )
    }
}
