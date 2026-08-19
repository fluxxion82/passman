package ai.passman.design.core

import ai.passman.design.core.button.ActionButton
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun SimpleTwoButtonHome(
    titleText: String,
    buttonOneText: String,
    buttonTwoText: String,
    onButtonOneClick: () -> Unit,
    onButtonTwoClick: () -> Unit
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
            Text(text = titleText, color = MaterialTheme.colorScheme.onPrimary)
        }

        ActionButton(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp, 50.dp, 20.dp, 0.dp),
            shape = RoundedCornerShape(80),
            // White pill on this screen's primary-painted root: stays borderless to match
            // the Login-family pills.
            containerColor = MaterialTheme.colorScheme.surface,
            buttonText = buttonOneText,
            buttonTextSize = 18,
            borderless = true,
            copyAction = onButtonOneClick,
        )

        ActionButton(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp, 50.dp, 20.dp, 0.dp),
            shape = RoundedCornerShape(80),
            containerColor = MaterialTheme.colorScheme.surface,
            buttonText = buttonTwoText,
            buttonTextSize = 18,
            borderless = true,
            copyAction = onButtonTwoClick
        )
    }
}
