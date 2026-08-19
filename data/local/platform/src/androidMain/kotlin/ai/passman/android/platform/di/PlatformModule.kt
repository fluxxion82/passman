package ai.passman.android.platform.di

import ai.passman.android.platform.connectivity.AndroidConnectionMonitor
import ai.passman.android.platform.network.AndroidIpAddressProvider
import ai.passman.crypto.kdf.JvmPasswordHasher
import ai.passman.crypto.kdf.PasswordHasher
import ai.passman.platform.crypto.JvmSecureRandomService
import ai.passman.platform.crypto.JvmSha256Service
import ai.passman.platform.crypto.SecureRandomService
import ai.passman.platform.crypto.Sha256Service
import ai.passman.platform.keyring.KeyringRepository
import ai.passman.platform.keyring.KeyringStore
import ai.passman.platform.network.IpAddressProvider
import ai.passman.platform.repository.FileTransferRepository
import ai.passman.platform.repository.LocalPasswordRepository
import ai.passman.platform.repository.LocalUserRepository
import ai.passman.platform.repository.PasswordEntryIdentity
import ai.passman.android.platform.service.ActivityProvider
import ai.passman.android.platform.service.AndroidAppSettingsService
import ai.passman.android.platform.service.AndroidSettingsService
import ai.passman.android.platform.service.AndroidBioAuthService
import ai.passman.android.platform.service.AndroidSystemClipboard
import ai.passman.platform.service.BioAuthService
import ai.passman.platform.service.ExpiringClipboard
import ai.passman.platform.di.commonPlatformModule
import ai.passman.platform.prefs.AndroidEncryptionSettingsFactory
import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.impl.ExpiryAwareClipboardPreferences
import ai.passman.platform.prefs.impl.LocalClipboardPreferences
import ai.passman.platform.prefs.impl.LocalThemePreferences
import ai.passman.platform.service.JvmKeystoreLifecycle
import ai.passman.platform.service.JvmPgpKeyRingService
import ai.passman.platform.service.KeystoreLifecycle
import ai.passman.platform.service.PgpKeyRingService
import ai.passman.platform.storage.JvmPasswordDatabaseStorage
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.recovery.JvmPortableVaultRecovery
import ai.passman.platform.recovery.JvmPortableVaultRepository
import ai.passman.platform.vault.JvmPortableCmsVaultFormat
import ai.passman.platform.vault.PortableVaultFormat
import ai.passman.domain.settings.repository.PortableVaultRepository
import ai.passman.platform.connectivity.JvmFingerprintService
import ai.passman.platform.transfer.JvmPasswordTransferService
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.connectivity.persistence.ConnectionMonitor
import ai.passman.domain.initialization.AppInitializer
import ai.passman.domain.password.repository.PasswordRepository
import ai.passman.domain.settings.repository.ClipboardPreferences
import ai.passman.domain.settings.repository.ThemePreferences
import ai.passman.domain.settings.repository.TransferRepository
import ai.passman.android.platform.service.AndroidQrCodeService
import ai.passman.domain.password.service.QrCodeService
import ai.passman.domain.settings.service.AppSettingsService
import ai.passman.domain.settings.service.SettingsService
import ai.passman.domain.user.repository.UserRepository
import com.russhwolf.settings.Settings
import com.russhwolf.settings.SharedPreferencesSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import org.koin.android.ext.koin.androidApplication
import org.koin.android.ext.koin.androidContext
import org.koin.dsl.bind
import org.koin.dsl.module

val platformModule = module {
    includes(commonPlatformModule)

    single<Settings.Factory> { SharedPreferencesSettings.Factory(androidContext()) }
    single<EncryptionSettingsFactory> { AndroidEncryptionSettingsFactory(androidContext()) }

    single<BioAuthService> { AndroidBioAuthService(activityProvider = get(), coroutinesContextFacade = get()) }
    single<PasswordDatabaseStorage> { JvmPasswordDatabaseStorage(platform = get()) }
    single<KeyringRepository> { KeyringStore(platform = get()) }
    single<KeystoreLifecycle> { JvmKeystoreLifecycle(keystoreClient = get()) }
    single<PgpKeyRingService> { JvmPgpKeyRingService(pgpClient = get()) }
    single<PasswordTransferService> { JvmPasswordTransferService(client = get()) }
    single<FingerprintService> {
        JvmFingerprintService(
            userPreferences = get(),
            hybridKeyManager = get(),
            mlDsaKeyManager = get(),
        )
    }
    single<IpAddressProvider> {
        AndroidIpAddressProvider(context = androidContext(), coroutinesContextFacade = get())
    }
    single<PasswordHasher> { JvmPasswordHasher() }
    single<SecureRandomService> { JvmSecureRandomService() }
    single { JvmPortableVaultRecovery(platform = get(), random = get()) }
    single<PortableVaultRepository> { JvmPortableVaultRepository(userPreferences = get(), recovery = get()) }
    single<PortableVaultFormat> { JvmPortableCmsVaultFormat(recovery = get()) }
    single<Sha256Service> { JvmSha256Service() }
    single { PasswordEntryIdentity(sha256 = get()) }

    single {
        ActivityProvider(application = androidApplication(), coroutinesScopeFacade = get(), foregroundEventPersistence = get())
    } bind AppInitializer::class

    single<AppSettingsService> { AndroidAppSettingsService(activityProvider = get()) }
    single<QrCodeService> { AndroidQrCodeService() }
    // The pending clear outlives the screen that copied it, so it runs on an app-lifetime scope of
    // its own rather than a view-model one. It uses the main dispatcher because ClipboardManager
    // is a UI-thread API on more OEM builds than the docs admit.
    //
    // It reads the *store* rather than the ClipboardPreferences binding below, which keeps the
    // graph acyclic: the decorator needs the coordinator, so the coordinator must not need the
    // decorator. Reads are identical either way — the decorator only adds a side effect on write.
    single {
        ExpiringClipboard(
            clipboard = AndroidSystemClipboard(context = androidContext()),
            preferences = get<LocalClipboardPreferences>(),
            scope = CoroutineScope(get<CoroutinesContextFacade>().main + SupervisorJob()),
        )
    }
    single<ClipboardPreferences> {
        ExpiryAwareClipboardPreferences(stored = get<LocalClipboardPreferences>(), clipboard = get())
    }
    single<ThemePreferences> {
        LocalThemePreferences(encryptedFactory = get(), coroutinesContextFacade = get())
    }
    single<SettingsService> {
        AndroidSettingsService(activityProvider = get(), context = androidContext(), clipboard = get())
    }
    single<ConnectionMonitor> { AndroidConnectionMonitor(context = androidContext(), contextFacade = get()) }

    single<UserRepository> {
        LocalUserRepository(
            platform = get(),
            coroutinesContextFacade = get(),
            userPreferences = get(),
            keystoreLifecycle = get(),
            pgpKeyRingService = get(),
            storage = get(),
            passwordHasher = get(),
            secureRandom = get(),
            bioAuthService = get(),
            keyringRepository = get(),
            vaultCipher = get(),
            portableVaultFormat = get(),
        )
    }
    single<PasswordRepository> {
        LocalPasswordRepository(
            userPreferences = get(),
            coroutinesContextFacade = get(),
            vaultCipher = get(),
            storage = get(),
            transferService = get(),
            entryIdentity = get(),
            portableVaultFormat = get(),
        )
    }
    single<TransferRepository> {
        FileTransferRepository(
            platform = get(),
            coroutineScopeFacade = get(),
            coroutinesContextFacade = get(),
            transferEventPersistence = get(),
            passwordEventPersistence = get(),
            passwordDatabaseStorage = get(),
            pgpEventPersistence = get(),
            keystoreEventPersistence = get(),
            userPreferences = get(),
            ipAddressProvider = get(),
            syncTlsProvider = get(),
            hybridKeyManager = get(),
            mlDsaKeyManager = get(),
            vaultCipher = get(),
            entryIdentity = get(),
            qrPairingSession = get(),
            portableVaultFormat = get(),
        )
    }
}
