package ai.passman.screens.ui.home

import ai.passman.design.core.getFileHandler
import ai.passman.design.core.model.MenuItem
import ai.passman.design.home.MainContent
import ai.passman.screens.ui.*
import ai.passman.screens.ui.passphrase.add.AddPassEntryScreen
import ai.passman.viewmodel.home.HomeViewModel
import ai.passman.viewvo.home.HomeNavigation
import ai.passman.viewmodel.passphrase.add.AddPassEntryViewModel
import ai.passman.domain.settings.model.ThemeMode
import androidx.compose.foundation.layout.RowScope
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.*
import androidx.navigation.NavController
import androidx.navigation.NavDestination.Companion.hasRoute
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import org.koin.compose.viewmodel.koinViewModel
import org.koin.core.annotation.KoinExperimentalAPI

val menuList = listOf(
    MenuItem("Password Management"),
    MenuItem("PGP Tools"),
    MenuItem("Keystore"),
    MenuItem("Settings"),
    MenuItem("Logout")
)

@OptIn(KoinExperimentalAPI::class)
@Composable
fun HomeScreen(
    outNavController: NavController,
    presenter: HomeViewModel,
    onThemeModeChanged: (ThemeMode) -> Unit,
) {
    val navController = rememberNavController()
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                HomeNavigation.KeystoreTools -> navController.navigate(KeystoreGraph)
                HomeNavigation.PgpTools -> navController.navigate(PgpGraph)
                HomeNavigation.PasswordManagement -> navController.navigate(PasswordGraph)
                HomeNavigation.AddPass -> navController.navigate(AddPassEntry)
                HomeNavigation.AddPgpKey -> navController.navigate(CreatePgpKey)
                HomeNavigation.AddKeystore -> navController.navigate(CreateKeystore)
                HomeNavigation.Settings -> navController.navigate(SettingsGraph)
                HomeNavigation.Logout -> outNavController.navigate(Splash) {
                    popUpTo<Home> {
                        inclusive = true
                    }
                }
            }
        }
    }

    val screenTitle = remember { mutableStateOf("PassMan") }
    var currentMenuItem by remember { mutableIntStateOf(0) }
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val snackbarHostState = remember { SnackbarHostState() }
    val showDrawer = remember { mutableStateOf(true) }
    val showBack = remember { mutableStateOf(false) }
    val showActionButton = remember { mutableStateOf(true) }
    val topBarActions = remember { mutableStateOf<@Composable RowScope.() -> Unit>({}) }
    val topBarOverride = remember { mutableStateOf<(@Composable () -> Unit)?>(null) }

    LaunchedEffect(presenter) {
        presenter.userMessages.receiveAsFlow().collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    val updateTitleText = remember {
        val updateTitle: (String, Boolean) -> Unit = { title, action ->
            showDrawer.value= true
            showBack.value = false

            showActionButton.value = action
            screenTitle.value = title
        }

        updateTitle
    }

    DisposableEffect(navController) {
        val listener = NavController.OnDestinationChangedListener { _, destination, _ ->
            topBarActions.value = {}
            topBarOverride.value = null
            when {
                destination.hasRoute(Settings::class) -> updateTitleText("Settings", false)
                destination.hasRoute(PasswordHome::class) -> updateTitleText("Passwords", true)
                destination.hasRoute(PgpHome::class) -> updateTitleText("PGP", true)
                destination.hasRoute(KeystoreHome::class) -> updateTitleText("KeyStores", true)
                else -> showActionButton.value = false
            }
        }
        navController.addOnDestinationChangedListener(listener)
        onDispose { navController.removeOnDestinationChangedListener(listener) }
    }

    MainContent(
        title = screenTitle.value,
        menuItems = menuList,
        showDrawer = showDrawer.value,
        showBackButton = showBack.value,
        showActionButton = showActionButton.value,
        drawerState = drawerState,
        snackbarHostState = snackbarHostState,
        fabMenu = if (currentMenuItem == 1 || currentMenuItem == 2) mapOf(
            "Import" to getFileHandler { path ->
                presenter.importFile(currentMenuItem, path)
            }::openFilePicker,
            "Create" to { presenter.onActionClick(currentMenuItem) },
        ) else mapOf(),
        onMenuItemClick = {
            currentMenuItem = menuList.indexOf(it)
            when (currentMenuItem) {
                0 -> presenter.onPasswordManagement()
                1 -> presenter.onPgpClick()
                2 -> presenter.onKeystoreClick()
                3 -> presenter.onSettingsClick()
                4 -> presenter.onLogoutClick()
            }
        },
        onActionButtonClick = {
            presenter.onActionClick(currentMenuItem)
        },
        onLeftButtonClick =  {
            if (showDrawer.value) {
                scope.launch {
                    drawerState.open()
                }
            } else if (showBack.value) {
                navController.navigateUp()
            }
        },
        topBarActions = topBarActions.value,
        topBarOverride = topBarOverride.value,
    ) {
        NavHost(
            navController = navController,
            startDestination = PasswordGraph,
        ) {
            passwordGraph(
                navController = navController,
                snackbarHostState = snackbarHostState,
                showDrawer = showDrawer,
                showBack = showBack,
                topBarActions = topBarActions,
                topBarOverride = topBarOverride,
            )

            pgpGraph(
                navController = navController,
                snackbarHostState = snackbarHostState,
                showDrawer = showDrawer,
                showBack = showBack,
                topBarActions = topBarActions,
                topBarOverride = topBarOverride,
            )

            keystoreGraph(
                navController = navController,
                snackbarHostState = snackbarHostState,
                showDrawer = showDrawer,
                showBack = showBack,
                topBarActions = topBarActions,
                topBarOverride = topBarOverride,
            )

            settingsGraph(
                navController = navController,
                snackbarHostState = snackbarHostState,
                showDrawer = showDrawer,
                showBack = showBack,
                onThemeModeChanged = onThemeModeChanged,
            )

            composable<AddPassEntry> {
                LaunchedEffect(Unit) {
                    showDrawer.value = false
                    showBack.value = true
                    showActionButton.value = false
                }

                // koinViewModel, NOT getKoin().get(): a bare factory get() mints a fresh view
                // model on every recomposition of this destination (and setting showBack above
                // recomposes HomeScreen), so the screen and any remembered callback ended up
                // talking to different instances — a picked QR filled a view model nothing
                // was displaying.
                val presenter: AddPassEntryViewModel = koinViewModel()
                AddPassEntryScreen(
                    navController = navController,
                    presenter = presenter,
                    snackbarHostState = snackbarHostState,
                )
            }
        }
    }
}
