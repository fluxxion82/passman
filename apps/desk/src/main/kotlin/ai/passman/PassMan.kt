package ai.passman

import ai.passman.di.config.buildConfigModule
import ai.passman.di.loggingModule
import ai.passman.design.PassmanTheme
import ai.passman.domain.di.domainModule
import ai.passman.platform.di.platformModule
import ai.passman.repo.di.jvmRepoModule
import ai.passman.repo.di.sharedRepoModule
import ai.passman.repo.di.toolsModule
import ai.passman.screens.ui.PassMan
import ai.passman.domain.base.invoke
import ai.passman.domain.initialization.InitializeApplication
import ai.passman.domain.settings.GetThemeMode
import ai.passman.domain.settings.model.ThemeMode
import ai.passman.viewmodel.di.viewModelModule
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowState
import androidx.compose.ui.window.application
import kotlinx.coroutines.InternalCoroutinesApi
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import org.koin.core.context.GlobalContext.startKoin

@OptIn(InternalCoroutinesApi::class, ExperimentalFoundationApi::class)
fun main() = application {
    val app = remember { App() }
    var themeMode by remember { mutableStateOf(ThemeMode.System) }
    var themeModeChangedByUser by remember { mutableStateOf(false) }
    LaunchedEffect(app) {
        app.initApplication()
    }
    LaunchedEffect(app) {
        val stored = app.getThemeMode()
        if (!themeModeChangedByUser) themeMode = stored
    }
    Window(
        onCloseRequest = ::exitApplication,
        title = "Passman",
        state = WindowState(size = DpSize(800.dp, 800.dp)),
    ) {
        PassmanTheme(themeMode = themeMode) {
            PassMan(onThemeModeChanged = {
                themeModeChangedByUser = true
                themeMode = it
            })
        }
    }
}

class App: KoinComponent {
    val initApplication: InitializeApplication by inject()
    val getThemeMode: GetThemeMode by inject()
    init {
        startKoin {
            modules(
                listOf(
                    buildConfigModule,
                    domainModule,
                    loggingModule,
                    viewModelModule,
                    platformModule,
                    toolsModule,
                    jvmRepoModule,
                    sharedRepoModule,
                )
            )
        }
    }
}
