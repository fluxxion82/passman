package ai.passman.design.core

import ai.passman.design.core.button.ActionButton
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun ButtonList(
    buttons: Map<String, ()-> Unit>
) {
    Column {
        buttons.forEach {
            ActionButton(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                shape = RoundedCornerShape(80),
                // White pill on the primary-painted HomeContent root: stays borderless to
                // match the Login-family pills.
                containerColor = MaterialTheme.colorScheme.surface,
                buttonText = it.key,
                buttonTextSize = 18,
                borderless = true,
                copyAction = it.value
            )
        }
    }
}
