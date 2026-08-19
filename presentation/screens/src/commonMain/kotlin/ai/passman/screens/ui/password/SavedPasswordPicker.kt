package ai.passman.screens.ui.password

import ai.passman.design.password.SecretPickerDialog
import ai.passman.design.password.SecretPickerItem
import ai.passman.viewmodel.password.SecretPickerViewModel
import ai.passman.viewmodel.password.applyTo
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import org.koin.compose.viewmodel.koinViewModel

/**
 * Hosts the saved-password picker for a screen and returns the "open it" action to hang off a
 * field's affordance.
 *
 * All of the picker's wiring lives here, at the screen layer, and none of it in the tool view
 * models: they never see [SecretPickerViewModel], [ai.passman.viewmodel.password.SecretPickerResult]
 * or the vault feed behind them. Each one only ever receives a plain string through the same
 * password setter the keyboard uses, so filling from the vault is indistinguishable — to the view
 * model, to the crypto call and to anything that logs either — from the user typing it.
 *
 * The picker view model comes from Koin against the current [androidx.lifecycle.ViewModelStoreOwner],
 * which under the nav host is the screen's back-stack entry: the session dies with the screen.
 *
 * Nothing about the choice is retained. There is no tool-to-entry association written anywhere,
 * this composable holds no state of its own, and the picker's result is a replay-free event, so the
 * password exists only in the moment between the tap and [onPasswordPicked].
 */
@Composable
fun rememberSavedPasswordPicker(onPasswordPicked: (String) -> Unit): () -> Unit {
    val picker: SecretPickerViewModel = koinViewModel()

    val visible by picker.visible.collectAsState()
    val query by picker.query.collectAsState()
    val rows by picker.rows.collectAsState()

    // Keyed on the view model alone. Re-keying on the callback would tear down and re-subscribe the
    // collector on every recomposition that produced a fresh lambda, and a result emitted in that
    // gap is gone for good — the flow has no replay by design.
    val currentOnPasswordPicked by rememberUpdatedState(onPasswordPicked)
    LaunchedEffect(picker) {
        picker.result.collect { result -> result.applyTo(currentOnPasswordPicked) }
    }

    // Navigating away does not clear the back-stack entry, so onCleared does not run and an open
    // session — its query, rows, and privately loaded vault entries — would stay live off-screen.
    // Leaving composition is the session boundary; dismissing an already-closed picker is a no-op.
    DisposableEffect(picker) {
        onDispose { picker.dismissPicker() }
    }

    if (visible) {
        SecretPickerDialog(
            query = query,
            items = rows.map { SecretPickerItem(id = it.uuid, name = it.entryName, username = it.username) },
            onQueryChanged = picker::onQueryChanged,
            onItemSelected = picker::onEntrySelected,
            onDismiss = picker::dismissPicker,
        )
    }

    return picker::openPicker
}
