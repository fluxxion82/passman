package ai.passman.screens.ui.splash

import ai.passman.viewmodel.splash.SplashViewModel
import androidx.compose.runtime.Composable
import androidx.navigation.NavController

@Composable
expect fun SplashScreen(
    navController: NavController,
    presenter: SplashViewModel,
)
