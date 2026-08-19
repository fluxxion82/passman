package ai.passman.design.settings

import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.formKeyboardNavigation
import ai.passman.design.core.passmanTextFieldColors

import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.TextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun TransferContent(
    isReceiving: Boolean?,
    ipAddress: String,
    inputValue: String,
    error: String,
    inputValueChanged: (String) -> Unit,
    onSendClick: () -> Unit,
    onReceiveClick: () -> Unit,
    onTransferClick: () -> Unit,
) {
    AnimatedContent(
        targetState = isReceiving,
        transitionSpec = {
            if (targetState == true) {
                slideIntoContainer(
                    towards = AnimatedContentTransitionScope.SlideDirection.Left,
                    animationSpec = tween(durationMillis = 400),
                ) togetherWith fadeOut(
                    animationSpec = tween(durationMillis = 400)
                )
            } else {
                fadeIn(
                    animationSpec = tween(durationMillis = 400),
                ) togetherWith slideOutOfContainer(
                    towards = AnimatedContentTransitionScope.SlideDirection.Right,
                    animationSpec = tween(durationMillis = 400)
                )
            }
        },
    ) {
        Column(
            modifier = Modifier.background(MaterialTheme.colorScheme.surface),
        ) {
            when (isReceiving) {
                true -> TransferReceive(ipAddress = ipAddress)
                false -> TransferSend(inputValue, inputValueChanged, onTransferClick)
                null -> {
                    GetTransferDirection(
                        onSendClick,
                        onReceiveClick,
                    )
                }
            }

            if (error.isNotEmpty()) {
                Text(
                    modifier = Modifier.fillMaxWidth().padding(10.dp),
                    text = "Error: $error",
                    fontSize = 16.sp,
                    fontFamily = FontFamily.Serif,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }

    }
}

@Composable
fun GetTransferDirection(
    onSendClick: () -> Unit,
    onReceiveClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .background(MaterialTheme.colorScheme.surface)
            .padding(10.dp),
    ) {
        // Standard primary buttons: the old raw primary fill had no edge against the white
        // surface backdrop (2.12:1).
        PassmanPrimaryButton(
            text = "Send",
            onClick = onSendClick,
            modifier = Modifier.fillMaxWidth(),
        )

        PassmanPrimaryButton(
            text = "Receive",
            onClick = onReceiveClick,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
fun TransferReceive(
    ipAddress: String,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .background(MaterialTheme.colorScheme.surface)
            .padding(10.dp),
    ) {
        Text(
            modifier = Modifier.fillMaxWidth().padding(10.dp),
            text = "Initiate password transfer in other application and enter this address in the requested field.",
            fontSize = 16.sp,
            fontFamily = FontFamily.SansSerif,
        )

        Text(
            modifier = Modifier.fillMaxWidth().padding(5.dp, 5.dp, 0.dp, 5.dp),
            text = ipAddress,
        )
    }
}

@Composable
fun TransferSend(
    inputValue: String,
    inputValueChanged: (String) -> Unit,
    onButtonClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        // On the send pane specifically: the address field is the only input, so Enter there
        // starts the transfer. The direction/receive panes have no fields to navigate.
        modifier = modifier
            .background(MaterialTheme.colorScheme.surface)
            .padding(10.dp)
            .formKeyboardNavigation(onSubmit = { onButtonClick(); true }),
    ) {
        Text(
            modifier = Modifier.fillMaxWidth().padding(5.dp),
            text = "Initiate password transfer in other application and type the given address in the field below.",
            fontSize = 16.sp,
            fontFamily = FontFamily.SansSerif,
        )

        TextField(
            modifier = Modifier
                .height(IntrinsicSize.Min)
                .padding(start = 0.dp, top = 5.dp, end = 0.dp, bottom = 5.dp)
                .fillMaxWidth(),
            value = inputValue,
            onValueChange = {
                inputValueChanged(it)
            },
            colors = passmanTextFieldColors(),
            singleLine = true,
            label = {
                Text(
                    text = "Address",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace,
                )
            }
        )

        PassmanPrimaryButton(
            text = "Transfer",
            onClick = onButtonClick,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
