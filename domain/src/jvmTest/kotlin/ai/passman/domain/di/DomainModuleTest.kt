package ai.passman.domain.di

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.GetPortableVaultAccess
import ai.passman.domain.settings.UpgradePortableVaultRecovery
import ai.passman.domain.settings.model.PortableVaultAccess
import ai.passman.domain.settings.repository.PortableVaultRepository
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import org.koin.core.context.startKoin
import org.koin.core.context.stopKoin
import org.koin.dsl.module

class DomainModuleTest {
    @AfterTest
    fun tearDown() {
        stopKoin()
    }

    @Test
    fun `provides portable vault access use case`() {
        val koin = startKoin {
            modules(
                domainModule,
                module {
                    single<PortableVaultRepository> {
                        object : PortableVaultRepository {
                            override suspend fun getAccess(): Outcome<PortableVaultAccess> =
                                error("The use case is resolved but not invoked in this test")

                            override suspend fun upgradeToBip39Phrase(): Outcome<PortableVaultAccess> =
                                error("The use case is resolved but not invoked in this test")
                        }
                    }
                },
            )
        }.koin

        assertIs<GetPortableVaultAccess>(koin.get<GetPortableVaultAccess>())
    }

    @Test
    fun `provides explicit portable vault recovery upgrade use case`() {
        val koin = startKoin {
            modules(
                domainModule,
                module {
                    single<PortableVaultRepository> {
                        object : PortableVaultRepository {
                            override suspend fun getAccess(): Outcome<PortableVaultAccess> =
                                error("The use case is resolved but not invoked in this test")

                            override suspend fun upgradeToBip39Phrase(): Outcome<PortableVaultAccess> =
                                error("The use case is resolved but not invoked in this test")
                        }
                    }
                },
            )
        }.koin

        assertIs<UpgradePortableVaultRecovery>(koin.get<UpgradePortableVaultRecovery>())
    }
}
