package ai.passman.design.splash

import ai.passman.design.core.passmanButtonColors

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DuelOptionContent(
    title: String,
    optionOneText: String,
    optionTwoText: String,
    onOptionOneClicked: () -> Unit,
    onOptionTwoClicked: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.primary)
            .padding(top = 100.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = title,
            fontSize = 18.sp,
            color = MaterialTheme.colorScheme.onPrimary,
            fontWeight = FontWeight.Bold
        )
        Button(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 50.dp, top = 50.dp, end = 50.dp)
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = ripple(bounded = false),
                    onClick = {}
                ),
            shape = RoundedCornerShape(80),
            colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
            onClick = { onOptionOneClicked() }
        ) {
            Text(
                text = optionOneText,
                fontSize = 18.sp,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
        }

        Button(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 50.dp, top = 50.dp, end = 50.dp)
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = ripple(bounded = false),
                    onClick = {}
                ),
            shape = RoundedCornerShape(80),
            colors = passmanButtonColors(containerColor = MaterialTheme.colorScheme.surface),
            onClick = { onOptionTwoClicked() }
        ) {
            Text(
                text = optionTwoText,
                fontSize = 18.sp,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
