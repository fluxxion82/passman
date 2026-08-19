package ai.passman.repo.di

import ai.passman.repo.DesktopPlatform
import ai.passman.repo.Platform
import org.koin.dsl.module

actual val sharedRepoModule = module {
    single<Platform> { DesktopPlatform() }
}

