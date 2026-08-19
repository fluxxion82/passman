package ai.passman.screens.ui

import ai.passman.screens.ui.home.HomeScreen
import ai.passman.screens.ui.keystore.KeystoreHomeScreen
import ai.passman.screens.ui.keystore.create.AddKeystoreKeyScreen
import ai.passman.screens.ui.keystore.create.CreateKeyStore
import ai.passman.screens.ui.keystore.crypt.KeystoreCryptScreen
import ai.passman.screens.ui.keystore.details.KeystoreDetailsScreen
import ai.passman.screens.ui.login.LoginScreen
import ai.passman.screens.ui.passphrase.PasswordHome
import ai.passman.screens.ui.passphrase.details.PassDetailsScreen
import ai.passman.screens.ui.pgp.PgpHomeScreen
import ai.passman.screens.ui.pgp.crypt.PgpToolsScreen
import ai.passman.screens.ui.pgp.keys.AddPgpKeyScreen
import ai.passman.screens.ui.pgp.keys.AddSubKeyScreen
import ai.passman.screens.ui.pgp.keys.ChangePasswordScreen
import ai.passman.screens.ui.pgp.keys.DeleteKeyScreen
import ai.passman.screens.ui.pgp.keys.ModifySubKeyScreen
import ai.passman.screens.ui.pgp.keys.PgpKeyDetailsScreen
import ai.passman.screens.ui.pgp.userid.add.AddUserIdScreen
import ai.passman.screens.ui.pgp.userid.remove.RemoveUserIdScreen
import ai.passman.screens.ui.settings.ReconcileScreen
import ai.passman.screens.ui.settings.SettingsScreen
import ai.passman.screens.ui.settings.TransferScreen
import ai.passman.screens.ui.settings.TrustedDevicesScreen
import ai.passman.screens.ui.signup.SignupScreen
import ai.passman.screens.ui.splash.SplashScreen
import ai.passman.viewmodel.home.HomeViewModel
import ai.passman.viewmodel.keystore.KeystoreHomeViewModel
import ai.passman.viewmodel.keystore.create.AddKeystoreKeyViewModel
import ai.passman.viewmodel.keystore.create.CreateKeyStoreViewModel
import ai.passman.viewmodel.keystore.crypt.KeystoreCryptViewModel
import ai.passman.viewmodel.keystore.details.KeystoreDetailsViewModel
import ai.passman.viewmodel.login.LoginViewModel
import ai.passman.viewmodel.passphrase.PasswordHomeViewModel
import ai.passman.viewmodel.passphrase.details.PassDetailsViewModel
import ai.passman.viewmodel.pgp.PgpHomeViewModel
import ai.passman.viewmodel.pgp.crypt.PgpCryptViewModel
import ai.passman.viewmodel.pgp.keys.ChangePasswordViewModel
import ai.passman.viewmodel.pgp.keys.DeleteKeyViewModel
import ai.passman.viewmodel.pgp.keys.ModifyPgpSubkeyViewModel
import ai.passman.viewmodel.pgp.keys.PgpAddKeyViewModel
import ai.passman.viewmodel.pgp.keys.PgpAddSubKeyViewModel
import ai.passman.viewmodel.pgp.keys.PgpKeyDetailsViewModel
import ai.passman.viewmodel.pgp.userid.add.AddUserIdViewModel
import ai.passman.viewmodel.pgp.userid.remove.RemoveUserIdViewModel
import ai.passman.viewmodel.settings.ReconcileViewModel
import ai.passman.viewmodel.connectivity.TrustedDevicesViewModel
import ai.passman.viewmodel.settings.SettingsViewModel
import ai.passman.viewmodel.settings.TransferViewModel
import ai.passman.viewmodel.signup.SignUpViewModel
import ai.passman.viewmodel.splash.SplashViewModel
import ai.passman.domain.settings.model.ThemeMode
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.ui.graphics.Color
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.dialog
import androidx.navigation.compose.navigation
import androidx.navigation.compose.rememberNavController
import androidx.navigation.toRoute
import kotlinx.coroutines.InternalCoroutinesApi
import org.koin.compose.viewmodel.koinViewModel
import org.koin.core.annotation.KoinExperimentalAPI
import org.koin.core.parameter.parametersOf

@OptIn(ExperimentalMaterial3Api::class)
@InternalCoroutinesApi
@ExperimentalFoundationApi
@Composable
fun PassMan(
    onThemeModeChanged: (ThemeMode) -> Unit,
) {
    val navController = rememberNavController()
    val snackbarHostState = remember { SnackbarHostState() }
    val showBack = remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            if (showBack.value) {
                TopAppBar(
                    title = { /* Your title if needed */ },
                    navigationIcon = {
                        IconButton(onClick = {
                            navController.navigateUp()
                        }) {
                            Icon(imageVector = Icons.AutoMirrored.Filled.ArrowBack, "back")
                        }
                    },
                    // Transparent so the bar floats over the screen instead of tinting a
                    // reserved strip; the onboard screens paint primary themselves. The icon
                    // color is pinned to what the primary-tinted bar used to resolve.
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = Color.Transparent,
                        navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                    )
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        // The conditional back bar handles the status-bar inset itself; without zeroing the
        // content insets, the scaffold pads the content by the status bar even when no bar
        // is shown, shoving every screen down by a white strip.
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
    ) { _ ->
        // The bar's height is deliberately NOT applied to the content: the back button
        // floats over the screen so the login/signup title keeps the same 100dp offset as
        // the welcome screen instead of dropping by the bar height. The only screens that
        // show this bar (Login/Signup) are non-scrolling and start their content below it.
        PassManContent(navController, snackbarHostState, showBack, onThemeModeChanged)
    }
}

@OptIn(KoinExperimentalAPI::class)
@InternalCoroutinesApi
@ExperimentalFoundationApi
@Composable
fun PassManContent(
    navController: NavHostController,
    snackbarHostState: SnackbarHostState,
    showBack: MutableState<Boolean>,
    onThemeModeChanged: (ThemeMode) -> Unit,
) = NavHost(
    navController = navController,
    startDestination = OnboardGraph,
) {
    onboardGraph(navController = navController, snackbarHostState = snackbarHostState, showBack)

    composable<Home> {
        LaunchedEffect(Unit) { showBack.value = false }
        val presenter: HomeViewModel = koinViewModel()
        HomeScreen(
            outNavController = navController,
            presenter = presenter,
            onThemeModeChanged = onThemeModeChanged,
        )
    }
}

fun NavGraphBuilder.onboardGraph(
    navController: NavController,
    snackbarHostState: SnackbarHostState,
    showBack: MutableState<Boolean>,
) = navigation<OnboardGraph>(startDestination = Splash) {
    composable<Splash> {
        LaunchedEffect(Unit) { showBack.value = false }
        val presenter: SplashViewModel = koinViewModel()
        SplashScreen(navController = navController, presenter = presenter)
    }
    composable<Signup> {
        LaunchedEffect(Unit) { showBack.value = true }
        val presenter: SignUpViewModel = koinViewModel()
        SignupScreen(navController = navController, presenter = presenter, snackbarHostState = snackbarHostState)
    }
    composable<Login> {
        LaunchedEffect(Unit) { showBack.value = true }
        val presenter: LoginViewModel = koinViewModel()
        LoginScreen(navController = navController, presenter = presenter, snackbarHostState = snackbarHostState)
    }
}

@OptIn(KoinExperimentalAPI::class)
fun NavGraphBuilder.passwordGraph(
    navController: NavController,
    snackbarHostState: SnackbarHostState,
    showDrawer: MutableState<Boolean>,
    showBack: MutableState<Boolean>,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
) = navigation<PasswordGraph>(startDestination = PasswordHome) {
    composable<PasswordHome> {
        LaunchedEffect(Unit) { showDrawer.value = true }
        val presenter: PasswordHomeViewModel = koinViewModel()
        PasswordHome(
            navController = navController,
            presenter = presenter,
            topBarActions = topBarActions,
            topBarOverride = topBarOverride,
            snackbarHostState = snackbarHostState,
        )
    }

    composable<PassEntryDetails> { backStackEntry ->
        LaunchedEffect(Unit) {
            showBack.value = true
            showDrawer.value = false
        }

        val route: PassEntryDetails = backStackEntry.toRoute()
        val presenter: PassDetailsViewModel = koinViewModel(parameters = { parametersOf(route.passEntryUuid) })
        PassDetailsScreen(
            navController = navController,
            presenter = presenter,
            snackbarHostState = snackbarHostState,
        )
    }
}

@OptIn(KoinExperimentalAPI::class)
fun NavGraphBuilder.pgpGraph(
    navController: NavController,
    snackbarHostState: SnackbarHostState,
    showDrawer: MutableState<Boolean>,
    showBack: MutableState<Boolean>,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
) = navigation<PgpGraph>(startDestination = PgpHome) {
    composable<PgpHome> {
        LaunchedEffect(Unit) {
            showDrawer.value = true
            showBack.value = false
        }
        val presenter: PgpHomeViewModel = koinViewModel()
        PgpHomeScreen(
            navController = navController,
            presenter = presenter,
            topBarActions = topBarActions,
            topBarOverride = topBarOverride,
            snackbarHostState = snackbarHostState,
        )
    }

    composable<CreatePgpKey> {
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val presenter: PgpAddKeyViewModel = koinViewModel()
        AddPgpKeyScreen(navController = navController, snackbarHostState = snackbarHostState, presenter = presenter)
    }

    composable<PgpKeyDetails> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpKeyDetails = backStackEntry.toRoute()
        val presenter: PgpKeyDetailsViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong()) })
        PgpKeyDetailsScreen(navController = navController, presenter = presenter, snackbarHostState = snackbarHostState)
    }

    composable<PgpTools> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpTools = backStackEntry.toRoute()
        val presenter: PgpCryptViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong(), route.action, route.isFileTarget) })
        PgpToolsScreen(navController = navController, snackbarHostState = snackbarHostState, presenter = presenter)
    }

    composable<PgpAddUserId> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpAddUserId = backStackEntry.toRoute()
        val presenter: AddUserIdViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong()) })
        AddUserIdScreen(navController = navController, presenter = presenter)
    }

    composable<PgpRemoveUserId> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpRemoveUserId = backStackEntry.toRoute()
        val presenter: RemoveUserIdViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong(), route.userId, route.action) })
        RemoveUserIdScreen(navController, presenter)
    }

    composable<PgpAddSubKey> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpAddSubKey = backStackEntry.toRoute()
        val presenter: PgpAddSubKeyViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong()) })
        AddSubKeyScreen(navController, snackbarHostState, presenter)
    }

    composable<PgpModifySubKey> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpModifySubKey = backStackEntry.toRoute()
        val presenter: ModifyPgpSubkeyViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong(), route.subKeyId, route.action) })
        ModifySubKeyScreen(navController, presenter)
    }

    composable<PgpChangePassword> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: PgpChangePassword = backStackEntry.toRoute()
        val presenter: ChangePasswordViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong()) })
        ChangePasswordScreen(navController, presenter)
    }

    dialog<PgpConfirmDelete> { backStackEntry ->
        LaunchedEffect(Unit) { showDrawer.value = false }
        val route: PgpConfirmDelete = backStackEntry.toRoute()
        val presenter: DeleteKeyViewModel = koinViewModel(parameters = { parametersOf(route.keyId.toLong()) })
        DeleteKeyScreen(navController, presenter)
    }
}

@OptIn(KoinExperimentalAPI::class)
fun NavGraphBuilder.keystoreGraph(
    navController: NavController,
    snackbarHostState: SnackbarHostState,
    showDrawer: MutableState<Boolean>,
    showBack: MutableState<Boolean>,
    topBarActions: MutableState<@Composable RowScope.() -> Unit>,
    topBarOverride: MutableState<(@Composable () -> Unit)?>,
) = navigation<KeystoreGraph>(startDestination = KeystoreHome) {
    composable<KeystoreHome> {
        LaunchedEffect(Unit) {
            showDrawer.value = true
            showBack.value = false
        }
        val presenter: KeystoreHomeViewModel = koinViewModel()
        KeystoreHomeScreen(
            navController = navController,
            presenter = presenter,
            topBarActions = topBarActions,
            topBarOverride = topBarOverride,
            snackbarHostState = snackbarHostState,
        )
    }

    composable<CreateKeystore> {
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val presenter: CreateKeyStoreViewModel = koinViewModel()
        CreateKeyStore(navController = navController, presenter = presenter, snackbarHostState = snackbarHostState)
    }

    composable<KeystoreDetails> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: KeystoreDetails = backStackEntry.toRoute()
        val presenter: KeystoreDetailsViewModel = koinViewModel(parameters = { parametersOf(route.keystorePath, route.keystoreName, "") })
        KeystoreDetailsScreen(
            navController = navController,
            presenter = presenter,
            snackbarHostState = snackbarHostState,
        )
    }

    composable<KeystoreTools> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: KeystoreTools = backStackEntry.toRoute()
        val presenter: KeystoreCryptViewModel = koinViewModel(
            parameters = { parametersOf(route.keystorePath, route.keystoreName, route.keyAlias, route.action, route.isFileTarget) }
        )
        KeystoreCryptScreen(
            navController = navController,
            snackbarHostState = snackbarHostState,
            presenter = presenter,
        )
    }

    composable<KeystoreAddKey> { backStackEntry ->
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val route: KeystoreAddKey = backStackEntry.toRoute()
        val presenter: AddKeystoreKeyViewModel = koinViewModel(parameters = { parametersOf(route.keystorePath, route.keystoreName) })
        AddKeystoreKeyScreen(navController = navController, snackbarHostState = snackbarHostState, presenter = presenter)
    }
}

@OptIn(KoinExperimentalAPI::class)
fun NavGraphBuilder.settingsGraph(
    navController: NavController,
    snackbarHostState: SnackbarHostState,
    showDrawer: MutableState<Boolean>,
    showBack: MutableState<Boolean>,
    onThemeModeChanged: (ThemeMode) -> Unit,
) = navigation<SettingsGraph>(startDestination = Settings) {
    composable<Settings> {
        // Main side-panel destination: drawer, no back button.
        LaunchedEffect(Unit) {
            showDrawer.value = true
            showBack.value = false
        }
        val presenter: SettingsViewModel = koinViewModel()
        SettingsScreen(
            navController = navController,
            presenter = presenter,
            snackbarHostState = snackbarHostState,
            onThemeModeChanged = onThemeModeChanged,
        )
    }

    dialog<TransferPasswords> {
        val presenter: TransferViewModel = koinViewModel()
        TransferScreen(
            presenter = presenter,
            navController = navController,
        )
    }

    dialog<ReconcileConflict> {
        val presenter: ReconcileViewModel = koinViewModel()
        ReconcileScreen(presenter = presenter, navController = navController)
    }

    composable<TrustedDevicesRoute> {
        // Deeper screen off Settings: show the top-bar back button (like PGP/keystore details).
        LaunchedEffect(Unit) {
            showDrawer.value = false
            showBack.value = true
        }
        val presenter: TrustedDevicesViewModel = koinViewModel()
        TrustedDevicesScreen(navController = navController, presenter = presenter)
    }
}
