package ai.passman.design.util

import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.platform.LocalContext

@Composable
actual fun PlatformBackHandler(enabled: Boolean, onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as? ComponentActivity
    val currentOnBack by rememberUpdatedState(onBack)

    DisposableEffect(enabled, activity) {
        val callback = object : OnBackPressedCallback(enabled) {
            override fun handleOnBackPressed() {
                currentOnBack()
            }
        }

        activity?.onBackPressedDispatcher?.addCallback(callback)

        onDispose {
            callback.remove()
        }
    }
}
