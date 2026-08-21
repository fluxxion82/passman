package ai.passman.repo.di

import ai.passman.keystore.JvmKeyStoreClient
import ai.passman.keystore.KeystoreClient
import ai.passman.pgp.service.PgpClient
import ai.passman.platform.transfer.ArtifactSyncClient
import ai.passman.platform.transfer.JvmKeystoreTransferService
import ai.passman.platform.transfer.JvmPgpTransferService
import ai.passman.platform.transfer.KeystoreTransferService
import ai.passman.platform.transfer.PgpTransferService
import ai.passman.repo.repositories.LocalKeystoreRepository
import ai.passman.domain.settings.repository.PreservedCopyRepository
import ai.passman.repo.repositories.LocalPreservedCopyRepository
import ai.passman.repo.repositories.LocalPgpRepository
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.keystore.repository.KeystoreRepository
import ai.passman.domain.pgp.repository.PgpRepository
import org.koin.dsl.module

val jvmRepoModule = module {
    single { PgpClient() }
    single<KeystoreClient> { JvmKeyStoreClient() }

    single { SyncTlsProvider(userPreferences = get(), trustedDevices = get()) }
    single {
        ai.passman.repo.crypto.HybridKeyManager(
            platform = get(),
            cryptoService = get(),
            userPreferences = get(),
            trustedDevices = get(),
        )
    }
    single {
        ai.passman.repo.crypto.MlDsaKeyManager(
            platform = get(),
            cryptoService = get(),
            userPreferences = get(),
            trustedDevices = get(),
        )
    }

    // Registered here rather than per platform module: all three transfer services (password included,
    // and that one is bound in data:local:platform) resolve this single instance.
    single {
        ArtifactSyncClient(syncTlsProvider = get(), hybridKeyManager = get(), mlDsaKeyManager = get())
    }

    single<PgpTransferService> { JvmPgpTransferService(client = get()) }
    single<KeystoreTransferService> { JvmKeystoreTransferService(client = get()) }

    single<PgpRepository> {
        LocalPgpRepository(
            platform = get(),
            coroutinesContextFacade = get(),
            pgpClient = get(),
            userPreferences = get(),
            pgpTransferService = get(),
            pgpPreferences = get(),
        )
    }

    single<PreservedCopyRepository> {
        LocalPreservedCopyRepository(
            platform = get(),
            userPreferences = get(),
            coroutinesContextFacade = get(),
        )
    }

    single<KeystoreRepository> {
        LocalKeystoreRepository(
            platform = get(),
            userPreferences = get(),
            keyStoreClient = get(),
            coroutinesContextFacade = get(),
            keystoreTransferService = get(),
        )
    }
}
