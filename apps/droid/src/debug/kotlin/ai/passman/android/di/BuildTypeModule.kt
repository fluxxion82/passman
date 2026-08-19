package ai.passman.android.di

import ai.passman.logging.Logger
import ai.passman.logging.android.AndroidLogger
import org.koin.dsl.bind
import org.koin.dsl.module

val buildTypeModule = module {
    single { AndroidLogger } bind Logger::class
}
