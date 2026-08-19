package ai.passman.repo.di

import ai.passman.repo.AndroidPlatform
import ai.passman.repo.Platform
import org.koin.android.ext.koin.androidContext
import org.koin.dsl.module

actual val sharedRepoModule = module {
    single<Platform> { AndroidPlatform(context = androidContext()) }
}
