package ai.passman.android

import ai.passman.android.di.buildConfigModule
import ai.passman.android.di.buildTypeModule
import ai.passman.android.di.loggingModule
import ai.passman.domain.di.domainModule
import ai.passman.android.platform.di.platformModule
import ai.passman.repo.di.jvmRepoModule
import ai.passman.repo.di.sharedRepoModule
import ai.passman.repo.di.toolsModule
import ai.passman.domain.base.invoke
import ai.passman.domain.initialization.InitializeApplication
import ai.passman.viewmodel.di.viewModelModule
import android.app.Application
import kotlinx.coroutines.runBlocking
import org.koin.android.ext.android.inject
import org.koin.android.ext.koin.androidContext
import org.koin.core.context.GlobalContext.startKoin

class PassManApplication : Application() {
    private val initializeApp: InitializeApplication by inject()

    override fun onCreate() {
        super.onCreate()

        registerKoin()

        runBlocking {
            initializeApp.invoke()
        }
    }

    private fun registerKoin() {
        startKoin {
            androidContext(this@PassManApplication)

            modules(
                listOf(
                    buildTypeModule,
                    buildConfigModule,
                    domainModule,
                    loggingModule,
                    platformModule,
                    toolsModule,
                    jvmRepoModule,
                    sharedRepoModule,
                    viewModelModule,
                )
            )
        }
    }
}
