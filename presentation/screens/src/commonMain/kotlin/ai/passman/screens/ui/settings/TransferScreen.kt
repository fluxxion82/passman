package ai.passman.screens.ui.settings

import ai.passman.design.settings.TransferContent
import ai.passman.screens.ui.ReconcileConflict
import ai.passman.screens.ui.Settings
import ai.passman.screens.ui.TrustedDevicesRoute
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.Reconcile
import ai.passman.viewmodel.settings.TransferViewModel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.flow.receiveAsFlow

@Composable
fun TransferScreen(presenter: TransferViewModel, navController: NavController) {
    val scope = rememberCoroutineScope()

    LaunchedEffect(scope) {
        presenter.navigation.receiveAsFlow().collect { event ->
            when (event) {
                is Back -> navController.navigateUp()

                Reconcile -> {
                    navController.navigate(ReconcileConflict) {
                        popUpTo<Settings>()
                    }
                }
            }
        }
    }

    val isReceiving by presenter.isReceiving.collectAsState()
    val ipAddress by presenter.receivingIpAddress.collectAsState()
    val inputAddress by presenter.inputAddress.collectAsState()
    val error by presenter.transferError.collectAsState()

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        TransferContent(
            isReceiving = isReceiving,
            ipAddress = ipAddress,
            inputValue = inputAddress,
            error = error,
            inputValueChanged = presenter::onInputAddressChanged,
            onSendClick = presenter::onSendClick,
            onReceiveClick = presenter::onReceiveClick,
            onTransferClick = presenter::onTransferClick,
        )
        TextButton(
            onClick = { navController.navigate(TrustedDevicesRoute) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
        ) {
            Text("Manage trusted devices")
        }
    }
}
