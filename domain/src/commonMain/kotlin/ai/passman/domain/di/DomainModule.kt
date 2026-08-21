@file:OptIn(ExperimentalTime::class)

package ai.passman.domain.di

import ai.passman.domain.app.ExitApp
import ai.passman.domain.app.persistence.ForegroundEventPersistence
import ai.passman.domain.app.persistence.InMemoryForegroundEventPersistence
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.DefaultScopeFacade
import ai.passman.domain.base.defaultContextFacade
import ai.passman.domain.connectivity.AddTrustedDevice
import ai.passman.domain.connectivity.BeginDevicePairing
import ai.passman.domain.connectivity.CancelDevicePairing
import ai.passman.domain.connectivity.ConfirmDevicePairing
import ai.passman.domain.connectivity.DismissPairingQr
import ai.passman.domain.connectivity.FetchPeerFingerprint
import ai.passman.domain.connectivity.GeneratePairingQrPayload
import ai.passman.domain.connectivity.GetArmedQrPairing
import ai.passman.domain.connectivity.GetOwnFingerprint
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.GetTrustedDevices
import ai.passman.domain.connectivity.ObserveQrPairingEvents
import ai.passman.domain.connectivity.PendingPairingState
import ai.passman.domain.connectivity.QrPairingSession
import ai.passman.domain.connectivity.RemoveTrustedDevice
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.identification.UpdateIdentifier
import ai.passman.domain.initialization.AppInitializer
import ai.passman.domain.initialization.GetAppVersion
import ai.passman.domain.initialization.InitializeApplication
import ai.passman.domain.keystore.AddKeyStoreEntry
import ai.passman.domain.keystore.AddKeystoreKey
import ai.passman.domain.keystore.ClearCryptoKeys
import ai.passman.domain.keystore.CreateKeyStore
import ai.passman.domain.keystore.EnsureDefaultKeystore
import ai.passman.domain.keystore.Decrypt
import ai.passman.domain.keystore.DeleteKeystore
import ai.passman.domain.keystore.DeleteKeystoreKey
import ai.passman.domain.keystore.Encrypt
import ai.passman.domain.keystore.GetAllKeystores
import ai.passman.domain.keystore.GetKeystore
import ai.passman.domain.keystore.GetKeystoreAliases
import ai.passman.domain.keystore.GetKeystoreKey
import ai.passman.domain.keystore.ImportKeystore
import ai.passman.domain.keystore.SignWithKey
import ai.passman.domain.keystore.VerifySignatureKeystore
import ai.passman.domain.keystore.persistence.InMemoryKeystoreEventPersistence
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.DecodeTotpQrImage
import ai.passman.domain.password.GenerateTotpCode
import kotlin.time.Clock
import kotlin.time.ExperimentalTime
import ai.passman.domain.password.DeletePassword
import ai.passman.domain.password.DeletePasswords
import ai.passman.domain.password.GetPassword
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.password.UpdatePassword
import ai.passman.domain.password.persistence.InMemoryPasswordEventPersistence
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.AddSubKey
import ai.passman.domain.pgp.ChangePgpKeyExpiry
import ai.passman.domain.pgp.ChangePgpKeyPassword
import ai.passman.domain.pgp.ChangeSubKeyExpiry
import ai.passman.domain.pgp.ClearSignPgp
import ai.passman.domain.pgp.CreatePgpKeyPair
import ai.passman.domain.pgp.DecryptAndVerify
import ai.passman.domain.pgp.DecryptPgp
import ai.passman.domain.pgp.DeletePgpKey
import ai.passman.domain.pgp.EncryptAndSignPgp
import ai.passman.domain.pgp.EncryptPgp
import ai.passman.domain.pgp.ExportPgpPrivateKey
import ai.passman.domain.pgp.GetAllPgpKeys
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.GetPgpPublicKeyPath
import ai.passman.domain.pgp.EnsureDefaultPgpRings
import ai.passman.domain.pgp.ImportDeveloperKey
import ai.passman.domain.pgp.ImportPgpKey
import ai.passman.domain.pgp.ModifySubKey
import ai.passman.domain.pgp.SignPgp
import ai.passman.domain.pgp.UpdateUserId
import ai.passman.domain.pgp.VerifyClearSignature
import ai.passman.domain.pgp.VerifySignaturePGP
import ai.passman.domain.pgp.persistence.InMemoryPgpEventPersistence
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.ClearSyncLog
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.domain.settings.GetClipboardExpiry
import ai.passman.domain.settings.GetPortableVaultAccess
import ai.passman.domain.settings.GetSyncLog
import ai.passman.domain.settings.GetThemeMode
import ai.passman.domain.settings.RecordSyncOutcome
import ai.passman.domain.settings.UpgradePortableVaultRecovery
import ai.passman.domain.settings.SetClipboardExpiry
import ai.passman.domain.settings.SetThemeMode
import ai.passman.domain.settings.ExecuteReconcileAction
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.GoToAppSettings
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.StartPairingServer
import ai.passman.domain.settings.StopPairingServer
import ai.passman.domain.settings.StartTransferServer
import ai.passman.domain.settings.StopTransferServer
import ai.passman.domain.settings.SyncKeystores
import ai.passman.domain.settings.SyncPasswords
import ai.passman.domain.settings.SyncPgpKeys
import ai.passman.domain.settings.TransferFile
import ai.passman.domain.settings.persistence.InMemoryTransferEventPersistence
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.domain.user.ChangeUserPassword
import ai.passman.domain.user.GeneratePassword
import ai.passman.domain.user.GetAppUser
import ai.passman.domain.user.GetBiometricAvailability
import ai.passman.domain.user.GetBiometricUnlockState
import ai.passman.domain.user.GetKnownUsernames
import ai.passman.domain.user.GetUserState
import ai.passman.domain.user.LoginAttemptThrottle
import ai.passman.domain.user.LoginUser
import ai.passman.domain.user.LogoutUser
import ai.passman.domain.user.OfferBiometricUnlock
import ai.passman.domain.user.RecordBiometricUnlockOffered
import ai.passman.domain.user.SetBiometricUnlock
import ai.passman.domain.user.SignUpUser
import ai.passman.domain.user.UpdateExistingUser
import ai.passman.domain.user.ValidateSignUpCredentials
import ai.passman.domain.user.UserInfoInitializer
import ai.passman.domain.user.persistences.InMemoryUserEventsPersistence
import ai.passman.domain.user.persistences.UserEventPersistence
import ai.passman.domain.user.services.UserAwareService
import org.koin.dsl.bind
import org.koin.dsl.module

val domainModule = module {
    factory<CoroutinesContextFacade> { defaultContextFacade() }
    factory<CoroutineScopeFacade> { DefaultScopeFacade(contextFacade = get()) }

    single<ForegroundEventPersistence> { InMemoryForegroundEventPersistence() }

    single { InitializeApplication(initializers = getKoin().getAll<AppInitializer>().toSet(), contextFacade = get()) }
    single { UpdateIdentifier(repository = get()) }
    single { GetAppVersion(appInformation = get()) }
    single { ExitApp() }

    // Keystore
    single<KeystoreEventPersistence> { InMemoryKeystoreEventPersistence(contextFacade = get()) }

    single { GetAllKeystores(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { GetKeystore(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { GetKeystoreAliases(keystoreRepository = get()) }
    single { AddKeyStoreEntry(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { ClearCryptoKeys(keystoreRepository = get(), cryptoPreferences = get()) }
    single { CreateKeyStore(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { AddKeystoreKey(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { DeleteKeystore(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { DeleteKeystoreKey(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { Decrypt(keystoreRepository = get()) }
    single { Encrypt(keystoreRepository = get()) }
    single { VerifySignatureKeystore(keystoreRepository = get()) }
    single { SignWithKey(keystoreRepository = get()) }
    single { ImportKeystore(keystoreRepository = get(), keystoreEventPersistence = get()) }
    single { GetKeystoreKey(keystoreRepository = get()) }
    single {
        EnsureDefaultKeystore(
            keystoreRepository = get(),
            passwordRepository = get(),
            keystorePreferences = get(),
            userPreferences = get(),
            generatePassword = get(),
            createKeyStore = get(),
            deleteKeystore = get(),
            addPassword = get(),
        )
    }

    // Password
    single<PasswordEventPersistence> { InMemoryPasswordEventPersistence(contextFacade = get()) }

    single { AddPassword(passwordRepository = get(), passwordEventPersistence = get()) }
    single { GetPasswordEntries(passwordRepository = get(), passwordEventPersistence = get()) }
    single { GetPassword(passwordRepository = get()) }
    single { UpdatePassword(passwordRepository = get(), passwordEventPersistence = get()) }
    single { GenerateTotpCode(epochSeconds = { Clock.System.now().epochSeconds }) }
    single { DecodeTotpQrImage(qrCodeService = get()) }
    single { DeletePassword(passwordRepository = get(), passwordEventPersistence = get()) }
    single { DeletePasswords(passwordRepository = get(), passwordEventPersistence = get()) }

    // PGP
    single<PgpEventPersistence> { InMemoryPgpEventPersistence(contextFacade = get()) }

    single { CreatePgpKeyPair(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ClearSignPgp(pgpRepository = get()) }
    single { DecryptPgp(pgpRepository = get()) }
    single { EncryptAndSignPgp(pgpRepository = get()) }
    single { EncryptPgp(pgpRepository = get()) }
    single { SignPgp(pgpRepository = get()) }
    single { VerifyClearSignature(pgpRepository = get()) }
    single { VerifySignaturePGP(pgpRepository = get()) }
    single { DecryptAndVerify(pgpRepository = get()) }
    single { GetAllPgpKeys(pgpRepository = get(), pgpEventPersistence = get()) }
    single { GetPgpKey(pgpRepository = get()) }
    single { GetPgpPublicKeyPath(pgpRepository = get()) }
    single { ExportPgpPrivateKey(pgpRepository = get()) }
    single { AddSubKey(pgpRepository = get(), pgpEventPersistence = get()) }
    single { UpdateUserId(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ChangePgpKeyExpiry(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ChangePgpKeyPassword(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ChangeSubKeyExpiry(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ModifySubKey(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ImportPgpKey(pgpRepository = get(), pgpEventPersistence = get()) }
    single { ImportDeveloperKey(pgpRepository = get(), pgpEventPersistence = get()) }
    single { DeletePgpKey(pgpRepository = get(), pgpEventPersistence = get()) }
    single {
        EnsureDefaultPgpRings(
            pgpRepository = get(),
            pgpPreferences = get(),
            passwordRepository = get(),
            userPreferences = get(),
            generatePassword = get(),
            addPassword = get(),
            pgpEventPersistence = get(),
        )
    }

    // Settings
    single { CopyToClipboard(repository = get()) }
    single { GetClipboardExpiry(preferences = get()) }
    single { GetPortableVaultAccess(repository = get()) }
    single { UpgradePortableVaultRecovery(repository = get()) }
    single { SetClipboardExpiry(preferences = get()) }
    single { GetThemeMode(preferences = get()) }
    single { SetThemeMode(preferences = get()) }
    single { GoToAppSettings(repository = get()) }
    single { TransferFile(passwordRepository = get()) }
    single { StartTransferServer(service = get()) }
    single { StopTransferServer(service = get()) }
    single { StartPairingServer(service = get()) }
    single { StopPairingServer(service = get()) }
    single { GetIpAddress(transferRepository = get()) }
    single { ExecuteReconcileAction(transferRepository = get(), passwordEventPersistence = get()) }
    single { ShareFile(settingsService = get()) }
    single { RecordSyncOutcome(syncLogRepository = get()) }
    single { GetSyncLog(repository = get()) }
    single { ClearSyncLog(repository = get()) }
    single {
        SyncPasswords(
            passwordRepository = get(),
            transferRepository = get(),
            trustedDevices = get(),
            fingerprintService = get(),
            passwordEventPersistence = get(),
            recordSyncOutcome = get(),
        )
    }
    single {
        SyncPgpKeys(
            pgpRepository = get(),
            transferRepository = get(),
            trustedDevices = get(),
            fingerprintService = get(),
            pgpEventPersistence = get(),
            recordSyncOutcome = get(),
        )
    }
    single {
        SyncKeystores(
            keystoreRepository = get(),
            transferRepository = get(),
            trustedDevices = get(),
            fingerprintService = get(),
            keystoreEventPersistence = get(),
            recordSyncOutcome = get(),
        )
    }

    // Trusted devices
    single { GetTrustedDevices(repository = get()) }
    single { GetSyncTargets(repository = get()) }
    single { UpdateTrustedDeviceHost(repository = get()) }
    single { AddTrustedDevice(repository = get(), userPreferences = get()) }
    single { RemoveTrustedDevice(repository = get()) }
    single { ai.passman.domain.connectivity.UpdateTrustedDeviceOps(repository = get()) }
    single { GetOwnFingerprint(fingerprintService = get()) }
    single { FetchPeerFingerprint(fingerprintService = get()) }
    single { PendingPairingState() }
    single { QrPairingSession(fingerprintService = get(), pendingPairingState = get()) }
    single { BeginDevicePairing(fingerprintService = get(), pendingPairingState = get(), userPreferences = get()) }
    single {
        ConfirmDevicePairing(
            trustedDevices = get(),
            fingerprintService = get(),
            pendingPairingState = get(),
            userPreferences = get(),
        )
    }
    single { CancelDevicePairing(pendingPairingState = get(), qrPairingSession = get()) }
    single {
        GeneratePairingQrPayload(
            fingerprintService = get(),
            qrPairingSession = get(),
            userPreferences = get(),
            transferRepository = get(),
        )
    }
    single { DismissPairingQr(qrPairingSession = get()) }
    single { ObserveQrPairingEvents(qrPairingSession = get()) }
    single { GetArmedQrPairing(pendingPairingState = get(), userPreferences = get()) }

    single<TransferEventPersistence> { InMemoryTransferEventPersistence(contextFacade = get()) }

    // User
    single<UserEventPersistence> { InMemoryUserEventsPersistence(contextFacade = get()) }
    single { ChangeUserPassword(userRepository = get(), userPreferences = get()) }

    single { GeneratePassword() }
    single { ValidateSignUpCredentials() }
    single { LoginAttemptThrottle() }
    single { GetAppUser(userEvents = get(), userPreferences = get()) }
    single { GetKnownUsernames(userPreferences = get()) }
    single { GetBiometricUnlockState(repository = get(), userPreferences = get()) }
    single { SetBiometricUnlock(repository = get(), userPreferences = get()) }
    single { OfferBiometricUnlock(repository = get(), userPreferences = get()) }
    single { RecordBiometricUnlockOffered(repository = get(), userPreferences = get()) }
    single { GetBiometricAvailability(repository = get()) }
    single { GetUserState(userPreferences = get(), userEvents = get()) }
    single {
        LoginUser(
            repository = get(),
            userPreferences = get(),
            getUserState = get(),
            userEventPersistence = get(),
            importDeveloperKey = get(),
            ensureDefaultKeystore = get(),
            ensureDefaultPgpRings = get(),
        )
    }
    single { LogoutUser(userPreferences = get(), cryptoPreferences = get(), userRepository = get(), userEvents = get()) }
    single {
        SignUpUser(
            repository = get(),
            getUserState = get(),
            userEventPersistence = get(),
            userPreferences = get(),
            importDeveloperKey = get(),
            ensureDefaultKeystore = get(),
            ensureDefaultPgpRings = get(),
            generatePassword = get(),
        )
    }
    single { UpdateExistingUser(preferences = get(), userEventPersistence = get()) }
    single {
        UserInfoInitializer(services = getKoin().getAll<UserAwareService>().toSet(), getAppUser = get(), scopeFacade = get())
    } bind AppInitializer::class
}
