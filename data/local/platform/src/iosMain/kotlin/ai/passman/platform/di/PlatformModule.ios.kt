package ai.passman.platform.di

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.IosEncryptionSettingsFactory
import ai.passman.platform.prefs.impl.LocalClipboardPreferences
import ai.passman.platform.prefs.impl.LocalThemePreferences
import ai.passman.domain.settings.repository.ClipboardPreferences
import ai.passman.domain.settings.repository.ThemePreferences
import com.russhwolf.settings.NSUserDefaultsSettings
import com.russhwolf.settings.Settings
import org.koin.core.module.Module
import org.koin.dsl.module

val platformModule: Module = module {
    includes(commonPlatformModule)

    single<Settings.Factory> { NSUserDefaultsSettings.Factory() }
    single<EncryptionSettingsFactory> { IosEncryptionSettingsFactory() }

    // The store as-is: there is no clipboard coordinator on iOS yet, so nothing to notify when the
    // setting is turned off. The JVM and Android modules bind this to a decorator that does.
    single<ClipboardPreferences> { get<LocalClipboardPreferences>() }
    single<ThemePreferences> {
        LocalThemePreferences(encryptedFactory = get(), coroutinesContextFacade = get())
    }

    // UserRepository, PasswordRepository, TransferRepository, SettingsService, AppSettingsService,
    // BioAuthService, BiometricUnlockRepository, ConnectionMonitor: intentionally not bound on iOS —
    // repository impls are still platform-specific (JVM-only crypto, file paths) and have no iOS
    // counterpart yet. Biometric unlock in particular needs a Secure Enclave key with
    // kSecAccessControlBiometryCurrentSet, which is the iOS port's job, not a stub's.
}
