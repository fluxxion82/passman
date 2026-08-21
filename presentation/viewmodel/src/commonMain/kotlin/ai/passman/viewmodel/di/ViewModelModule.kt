package ai.passman.viewmodel.di

import ai.passman.viewmodel.home.HomeViewModel
import ai.passman.viewmodel.keystore.KeystoreHomeViewModel
import ai.passman.viewmodel.keystore.create.AddKeystoreKeyViewModel
import ai.passman.viewmodel.keystore.create.CreateKeyStoreViewModel
import ai.passman.viewmodel.keystore.crypt.KeystoreCryptViewModel
import ai.passman.viewmodel.keystore.details.KeystoreDetailsViewModel
import ai.passman.viewmodel.login.LoginViewModel
import ai.passman.viewmodel.passphrase.PasswordHomeViewModel
import ai.passman.viewmodel.passphrase.add.AddPassEntryViewModel
import ai.passman.viewmodel.passphrase.details.PassDetailsViewModel
import ai.passman.viewmodel.password.SecretPickerViewModel
import ai.passman.viewmodel.pgp.PgpHomeViewModel
import ai.passman.viewmodel.pgp.crypt.PgpCryptViewModel
import ai.passman.viewmodel.pgp.keys.*
import ai.passman.viewmodel.pgp.userid.add.AddUserIdViewModel
import ai.passman.viewmodel.pgp.userid.remove.RemoveUserIdViewModel
import ai.passman.viewmodel.settings.ReconcileViewModel
import ai.passman.viewmodel.settings.SettingsViewModel
import ai.passman.viewmodel.settings.TransferViewModel
import ai.passman.viewmodel.signup.SignUpViewModel
import ai.passman.viewmodel.splash.SplashViewModel
import ai.passman.viewmodel.sync.PreservedCopiesViewModel
import ai.passman.viewmodel.sync.SyncActivityViewModel
import org.koin.core.module.dsl.viewModel
import org.koin.dsl.module

val viewModelModule = module {
    viewModel { SplashViewModel() }
    viewModel {
        LoginViewModel(
            loginUser = get(),
            getKnownUsernames = get(),
            loginAttemptThrottle = get(),
            getBiometricUnlockState = get(),
            offerBiometricUnlock = get(),
            setBiometricUnlock = get(),
        )
    }
    viewModel {
        SignUpViewModel(
            signUpUser = get(),
            validateSignUpCredentials = get(),
            getBiometricAvailability = get(),
            setBiometricUnlock = get(),
            recordBiometricUnlockOffered = get(),
        )
    }
    viewModel { HomeViewModel(importPgpKeys = get(), importKeystore = get(), logoutUser = get()) }
    viewModel {
        PasswordHomeViewModel(
            getPasswordEntries = get(),
            syncPasswords = get(),
            getSyncTargets = get(),
            updateTrustedDeviceHost = get(),
            deletePasswords = get(),
        )
    }
    viewModel {
        ai.passman.viewmodel.connectivity.TrustedDevicesViewModel(
            getTrustedDevices = get(),
            removeTrustedDevice = get(),
            updateTrustedDeviceOps = get(),
            getOwnFingerprint = get(),
            getIpAddress = get(),
            beginDevicePairing = get(),
            confirmDevicePairing = get(),
            cancelDevicePairing = get(),
            startPairingServer = get(),
            stopPairingServer = get(),
            generatePairingQrPayload = get(),
            dismissPairingQr = get(),
            observeQrPairingEvents = get(),
            getArmedQrPairing = get(),
            copyToClipboard = get(),
        )
    }
    viewModel {
        SettingsViewModel(
            changeUserPassword = get(),
            getClipboardExpiry = get(),
            setClipboardExpiry = get(),
            getThemeMode = get(),
            setThemeMode = get(),
            getBiometricUnlockState = get(),
            setBiometricUnlock = get(),
            getAppVersion = get(),
            getPortableVaultAccess = get(),
            copyToClipboard = get(),
            upgradePortableVaultRecovery = get(),
        )
    }
    // Shared between the screens that can fill a password field from the vault. Every session is
    // reset by SecretPickerViewModel.openPicker(), so a shared instance still starts clean.
    viewModel { SecretPickerViewModel(getPasswordEntries = get()) }

    viewModel {
        AddPassEntryViewModel(
            addPassword = get(),
            passwordEventPersistence = get(),
            generateTotpCode = get(),
            decodeTotpQrImage = get(),
        )
    }
    viewModel { params ->
        PassDetailsViewModel(
            passwordUuid = params[0],
            getPassword = get(),
            updatePassword = get(),
            deletePassword = get(),
            copyToClipboard = get(),
            generateTotpCode = get(),
            decodeTotpQrImage = get(),
        )
    }
    viewModel {
        KeystoreHomeViewModel(
            getAllKeystores = get(),
            syncKeystores = get(),
            getSyncTargets = get(),
            updateTrustedDeviceHost = get(),
            deleteKeystore = get(),
            getAppUser = get(),
        )
    }
    viewModel { CreateKeyStoreViewModel(createKeyStore = get(), addPassword = get()) }
    viewModel { params ->
        KeystoreDetailsViewModel(
            keystorePath = params[0],
            keystoreName = params[1],
            getKeystore = get(),
            getKeystoreAliases = get(),
            deleteKeystore = get(),
            deleteKeystoreKey = get(),
            shareFile = get(),
        )
    }
    viewModel { params ->
        AddKeystoreKeyViewModel(
            keystorePath = params[0],
            keystoreName = params[1],
            getKeystore = get(),
            addKeystoreKey = get(),
            addPassword = get(),
        )
    }
    viewModel { params ->
        KeystoreCryptViewModel(
            keystorePath = params[0],
            keystoreName = params[1],
            keyAlias = params[2],
            initialAction = params[3],
            initialFileTarget = params[4],
            getKeystoreKey = get(),
            encrypt = get(),
            decrypt = get(),
            sign = get(),
            verifySignatureKeystore = get(),
            copyToClipboard = get(),
        )
    }
    viewModel {
        PgpHomeViewModel(
            getAllKeys = get(),
            syncPgpKeys = get(),
            getSyncTargets = get(),
            updateTrustedDeviceHost = get(),
            deletePgpKey = get(),
            importDeveloperKey = get(),
        )
    }
    viewModel { PgpAddKeyViewModel(createPgpKey = get(), addPassword = get()) }
    viewModel { params ->
        PgpCryptViewModel(
            keyId = params[0],
            initialAction = params[1],
            initialFileTarget = params[2],
            getPgpKey = get(),
            encryptPgp = get(),
            decryptPgp = get(),
            clearSign = get(),
            encryptAndSignPgp = get(),
            decryptAndVerifyPgp = get(),
            verifyClearSignature = get(),
            copyToClipboard = get(),
        )
    }
    viewModel { params ->
        PgpKeyDetailsViewModel(
            keyId = params[0],
            getPgpKey = get(),
            getPgpPublicKeyPath = get(),
            exportPgpPrivateKey = get(),
            shareFile = get(),
            pgpEventPersistence = get(),
        )
    }
    viewModel { params ->
        DeleteKeyViewModel(
            keyId = params[0],
            deletePgpKey = get(),
        )
    }
    viewModel { params ->
        AddUserIdViewModel(
            keyId = params[0],
            getPgpKey = get(),
            updateUserId = get(),
        )
    }
    viewModel { params ->
        RemoveUserIdViewModel(
            keyId = params[0],
            userId = params[1],
            userIdAction = params[2],
            getPgpKey = get(),
            updateUserId = get(),
        )
    }
    viewModel { parans ->
        PgpAddSubKeyViewModel(
            keyId = parans[0],
            getPgpKey = get(),
            addSubKey = get(),
        )
    }
    viewModel { params ->
        ModifyPgpSubkeyViewModel(
            keyId = params[0],
            subkeyId = params[1],
            action = params[2],
            getPgpKey = get(),
            modifySubKey = get(),
        )
    }
    viewModel { params ->
        ChangePasswordViewModel(
            keyId = params[0],
            getPgpKey = get(),
            changePassword = get(),
        )
    }
    viewModel {
        TransferViewModel(
            transferFile = get(),
            getIpAddress = get(),
            startTransferServer = get(),
            stopTransferServer = get(),
            getSyncTargets = get(),
            transferEventPersistence = get(),
        )
    }
    viewModel { ReconcileViewModel(executeReconcileAction = get()) }
    viewModel { SyncActivityViewModel(getSyncLog = get(), clearSyncLog = get()) }
    viewModel {
        PreservedCopiesViewModel(
            getPreservedCopies = get(),
            restorePreservedCopy = get(),
            deletePreservedCopy = get(),
            getPreservedCopyPath = get(),
            shareFile = get(),
        )
    }
}
