package ai.passman.design.core

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusDirection
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalFocusManager

/**
 * Desktop-grade keyboard behavior for a form: Tab / Shift+Tab move focus between fields, and Enter
 * submits via [onSubmit] when the focused node did not want the key for itself.
 *
 * Apply to the root layout of a form screen. For dialogs it MUST be composed INSIDE the dialog's
 * content lambda (on the content root, e.g. the `Column` in an `AlertDialog`'s `text` slot) —
 * never passed through the dialog's `modifier` parameter. A dialog is a separate window with its
 * own focus owner; a modifier built in the host screen's composition captures the HOST's
 * `LocalFocusManager`, so Tab would traverse the wrong tree and `clearFocus()` would leave the
 * dialog's field focused (letting an auto-repeated Enter re-fire the confirm).
 *
 * Why two handlers:
 * - Tab lives in `onPreviewKeyEvent` because preview dispatches root-first, ancestor before the
 *   focused child. Running before the focused node beats both the multiline text-field handler
 *   that would otherwise commit a literal `\t` and the `ExposedDropdownMenuBox` anchor's own
 *   Tab consume while its menu is expanded. Tab is always consumed here — by decision, no field
 *   in the app accepts a typed tab character (pasting tabs is unaffected) — so even when focus
 *   cannot move the event never falls through to insert `\t`.
 * - Enter lives in the post `onKeyEvent`, which dispatches focused-child-first with the root
 *   last, so it only fires when the focused node declined the key. A multiline field consumes
 *   Enter to insert its newline and a focused button consumes Enter to click, both before this
 *   handler; a single-line field runs its no-op default IME action and lets the key bubble up
 *   to submit. Android's soft-keyboard Enter never reaches hardware key handlers, so this is
 *   desktop-only behavior with no mobile regression.
 *
 * [onSubmit] returns whether it actually submitted — it should run the same gate as the primary
 * button's `enabled` condition and return false when the gate declines (loading, empty required
 * field). The gate runs FIRST: only a true return clears focus and consumes the event, so a
 * declined Enter leaves focus where it was and lets the key propagate untouched.
 */
@Composable
fun Modifier.formKeyboardNavigation(onSubmit: (() -> Boolean)? = null): Modifier {
    val focusManager = LocalFocusManager.current
    return this
        .onPreviewKeyEvent { event ->
            if (event.type == KeyEventType.KeyDown && event.key == Key.Tab) {
                focusManager.moveFocus(
                    if (event.isShiftPressed) FocusDirection.Previous else FocusDirection.Next,
                )
                // Consume even when focus could not move: an unconsumed Tab reaches the focused
                // multiline field's post handler and types a tab character.
                true
            } else {
                false
            }
        }
        .onKeyEvent { event ->
            if (onSubmit != null &&
                event.type == KeyEventType.KeyDown &&
                (event.key == Key.Enter || event.key == Key.NumPadEnter)
            ) {
                if (onSubmit()) {
                    focusManager.clearFocus()
                    true
                } else {
                    false
                }
            } else {
                false
            }
        }
}
