package ai.passman.design.home

import ai.passman.design.core.ButtonList
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun HomeContent(
    onPasswordMgmt: () -> Unit,
    onKeyMgmtClick: () -> Unit,
    onCryptoClick: () -> Unit,
    onLogoutClick: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
            modifier = Modifier
                .fillMaxWidth()
                .padding(0.dp, 50.dp, 0.dp, 0.dp)
        ) {
            Text(
                text = "Choose Option",
                color = MaterialTheme.colorScheme.onPrimary,
            ) // stringResource(id = R.string.choose_option)
        }

        ButtonList(
            mapOf(
                "Password Management" to onPasswordMgmt,
                "Key Management" to onKeyMgmtClick,
                "Crypto Tools" to onCryptoClick,
                "Logout" to onLogoutClick,
            )
        )
    }
}
