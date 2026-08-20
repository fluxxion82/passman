package ai.passman

import ai.passman.di.config.buildConfigModule
import ai.passman.di.buildVariantModule
import ai.passman.di.loggingModule
import ai.passman.design.PassmanTheme
import ai.passman.domain.di.domainModule
import ai.passman.platform.di.platformModule
import ai.passman.repo.Platform
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.WindowState
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.application
import java.io.File
import javax.swing.JOptionPane
import kotlinx.coroutines.InternalCoroutinesApi
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import org.koin.core.context.GlobalContext.startKoin

fun main() {
    val app = App()

    // Before a single window is composed, and before anything touches the vault. Two copies of this
    // app against one data directory share a vault file, a prefs node and a credential-store key,
    // and both try to bind the sync listener on the same port - which surfaces to the user as
    // "address already in use" on one device and "Connection reset" on its peer, neither of which
    // mentions a second window being open. Koin is started by App() but every binding is lazy, so
    // nothing has been read or written at this point.
    //
    // A plain dialog rather than a Compose window: this runs before `application { }` exists, and
    // a second instance should not get as far as building a UI.
    if (!InstanceLock().claim(File(app.localPath))) {
        JOptionPane.showMessageDialog(
            null,
            "Passman is already open.\n\nAnother window is using this vault, so this one has not " +
                "started. Switch to it, or close it and try again.\n\n${app.localPath}",
            "Passman",
            JOptionPane.WARNING_MESSAGE,
        )
        return
    }

    application { PassManApplication(app) }
}

@OptIn(InternalCoroutinesApi::class, ExperimentalFoundationApi::class)
@Composable
private fun ApplicationScope.PassManApplication(app: App) {
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

    /** The profile's data directory, which is what an instance claims. */
    val localPath: String get() = platform.getLocalPath()

    private val platform: Platform by inject()
    init {
        startKoin {
            modules(
                listOf(
                    // First: everything variant-dependent resolves DesktopProfile from here.
                    buildVariantModule,
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
