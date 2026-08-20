package ai.passman.design.biometric

import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.button.PassmanSecondaryButton
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/**
 * The one-time offer to enrol, shown on the way into the app by whichever screen just authenticated.
 *
 * There is no password field, and that absence is the point. Both screens that raise this still hold
 * the plaintext the user typed a second ago; after this frame the app has only the stored hash and
 * salt, which is why the settings toggle has to ask for the password all over again. Offering here
 * is the difference between a feature people find and one that needs looking for.
 *
 * Dismissal is "not now" rather than a third answer: the account's single offer has already been
 * spent by the time this is composed, and leaving a back press unhandled would strand the user on a
 * login screen they have already passed.
 *
 * @param isEnrolling true while the system prompt is up, during which the dialog stops accepting
 * anything — same rule as the settings enrol dialog, and for the same reason: navigating away kills
 * the ViewModel that is waiting on the prompt.
 */
@Composable
fun BiometricEnrolmentOfferDialog(
    isEnrolling: Boolean,
    onEnable: () -> Unit,
    onNotNow: () -> Unit,
) {
    Dialog(
        onDismissRequest = { if (!isEnrolling) onNotNow() },
        properties = DialogProperties(
            dismissOnBackPress = !isEnrolling,
            dismissOnClickOutside = !isEnrolling,
        ),
    ) {
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurface,
        ) {
            Column(
                modifier = Modifier
                    .wrapContentHeight()
                    .fillMaxWidth()
                    .padding(24.dp),
            ) {
                Icon(
                    imageVector = Icons.Filled.Fingerprint,
                    contentDescription = null,
                    modifier = Modifier.size(32.dp),
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    text = "Unlock with your fingerprint next time?",
                    style = MaterialTheme.typography.titleMedium,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Your master password is sealed under a key this device's hardware only " +
                        "releases after your biometric matches. Changing your master password, or " +
                        "the biometrics registered on this device, turns it back off.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(16.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    PassmanSecondaryButton(
                        text = "Not now",
                        enabled = !isEnrolling,
                        onClick = onNotNow,
                    )
                    Spacer(Modifier.width(8.dp))
                    PassmanPrimaryButton(
                        enabled = !isEnrolling,
                        onClick = onEnable,
                    ) {
                        if (isEnrolling) {
                            CircularProgressIndicator(
                                modifier = Modifier
                                    .padding(end = 8.dp)
                                    .size(16.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                strokeWidth = 2.dp,
                            )
                        }
                        Text("Turn on", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}
