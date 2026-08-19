package ai.passman.screens.ui.settings

import ai.passman.design.settings.ReconcileContent
import ai.passman.viewvo.navigation.Back
import ai.passman.viewmodel.settings.ReconcileViewModel
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun ReconcileScreen(navController: NavController, presenter: ReconcileViewModel) {
    val scope = rememberCoroutineScope()
    val errorMessage by presenter.reconcileError.collectAsState()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is Back -> navController.navigateUp()
            }
        }
    }

    ReconcileContent(
        onMerge = presenter::onMergeClicked,
        onOverwrite = presenter::onOverwriteClicked,
        onDelete = presenter::onDeleteClicked,
        onDismiss = navController::navigateUp,
        errorMessage = errorMessage,
    )
}
