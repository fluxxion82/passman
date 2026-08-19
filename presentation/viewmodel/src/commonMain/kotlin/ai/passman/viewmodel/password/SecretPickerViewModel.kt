package ai.passman.viewmodel.password

import ai.passman.domain.base.invoke
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** One row of the picker list. Carries what the user needs to recognise an entry, and nothing else. */
data class SecretPickerRow(
    val uuid: String,
    val entryName: String,
    val username: String,
)

/**
 * What a picker session produced, handed to the requesting screen exactly once.
 *
 * [Selected] is the only object in this feature that holds a password. It is delivered as an event
 * on [SecretPickerViewModel.result] and is never retained afterwards.
 */
sealed interface SecretPickerResult {
    data class Selected(val password: String) : SecretPickerResult
    data object Cancelled : SecretPickerResult
}

/**
 * Route a session's outcome into the field the user opened the picker for.
 *
 * This is the whole of the caller side, and it lives here rather than in each requesting view model
 * on purpose. The PGP and keystore crypt view models already own a `onPasswordChanged`-shaped
 * setter for the keyboard; giving them a picker dependency as well would put a live vault feed and
 * a delivered password inside a view model whose job is to run one crypto operation. Their screens
 * collect [SecretPickerViewModel.result] and pass the setter here instead, so the view models stay
 * free of picker types entirely — pinned by the structural tests in `PgpCryptViewModelTest` and
 * `KeystoreCryptViewModelTest`.
 *
 * Only [SecretPickerResult.Selected] touches the field. [SecretPickerResult.Cancelled] deliberately
 * does nothing at all — backing out of the picker is not an edit, and a cancel that blanked the
 * field would throw away a password the user had typed by hand.
 */
fun SecretPickerResult.applyTo(setPassword: (String) -> Unit) {
    when (this) {
        is SecretPickerResult.Selected -> setPassword(password)
        SecretPickerResult.Cancelled -> Unit
    }
}

/**
 * Lets a tool screen fill a password field from the vault without going through the clipboard.
 *
 * Everything here is ephemeral by construction:
 *
 * - the vault is read only while a session is open, and the entries are dropped the moment it ends,
 *   so no password sits in memory between sessions;
 * - the list state holds [SecretPickerRow]s, never [PasswordEntry]s — a row the UI renders or a log
 *   line that prints the state cannot leak a secret;
 * - the chosen password is *delivered*, not *held*: [result] is a replay-free event stream, so a
 *   password reaches whoever is collecting at the moment of the tap and cannot be read back out of
 *   this view model afterwards by a recreated host, a second collector, or a late one;
 * - there is no clipboard dependency at all. Avoiding the clipboard is the entire point of the
 *   feature, so the capability is absent rather than merely unused.
 *
 * Koin hands out one instance per screen graph, so a "fresh session" is established by
 * [openPicker] resetting the state rather than by construction.
 */
class SecretPickerViewModel(
    private val getPasswordEntries: GetPasswordEntries,
) : BaseViewModel() {

    private val _visible = MutableStateFlow(false)
    val visible: StateFlow<Boolean> = _visible.asStateFlow()

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    private val _rows = MutableStateFlow<List<SecretPickerRow>>(emptyList())
    val rows: StateFlow<List<SecretPickerRow>> = _rows.asStateFlow()

    /**
     * The session's outcome, as an event rather than as state.
     *
     * `replay = 0` is the security property. A held [SecretPickerResult.Selected] — the shape a
     * `StateFlow` or any replaying holder would force — outlives the session for as long as the
     * caller neglects to clear it, and hands the password to every collector that attaches later.
     * Here the value reaches the collectors subscribed at the moment of the tap and is then gone.
     *
     * The single buffer slot exists only so that [deliver] can hand a value to a subscribed
     * collector without suspending; with `extraBufferCapacity = 0`, `tryEmit` fails outright
     * whenever a collector is attached. It is not a replay cache: a value emitted while nobody is
     * collecting is dropped, and a value buffered for a collector that goes away before taking it
     * is not handed to the next one. Both are pinned in `SecretPickerViewModelTest`.
     */
    private val _result = MutableSharedFlow<SecretPickerResult>(replay = 0, extraBufferCapacity = 1)
    val result: SharedFlow<SecretPickerResult> = _result.asSharedFlow()

    /**
     * The open session's entries. Deliberately not a published state flow: these carry passwords,
     * and only [rows] is fit to be observed. Cleared whenever the session ends.
     */
    private var loadedEntries: List<PasswordEntry> = emptyList()
    private var loadJob: Job? = null

    /** Start a session. Any leftover query or list from the last one is dropped. */
    fun openPicker() {
        endSession()
        _visible.value = true
        loadJob = viewModelScope.launch {
            getPasswordEntries().collect { entries ->
                loadedEntries = entries
                publishRows()
            }
        }
    }

    fun onQueryChanged(query: String) {
        _query.value = query
        publishRows()
    }

    /**
     * Publish the chosen entry's password and close the session.
     *
     * A [uuid] that is no longer in the list — the vault changed under the user — produces no
     * result at all; guessing at a neighbouring entry would hand a tool the wrong secret.
     */
    fun onEntrySelected(uuid: String) {
        val password = loadedEntries.firstOrNull { it.uuid == uuid }?.password ?: return
        endSession()
        deliver(SecretPickerResult.Selected(password))
    }

    /** Abandon the session. */
    fun dismissPicker() {
        endSession()
        deliver(SecretPickerResult.Cancelled)
    }

    override fun onCleared() {
        super.onCleared()
        endSession()
    }

    /**
     * Hand the outcome to whoever is collecting, without suspending.
     *
     * `tryEmit` returning `false` means the previous session's result is still sitting in the buffer
     * unread, and dropping this one is the right outcome: the alternative is a growing queue of
     * results — one of them a password — waiting for a collector that may never come back.
     */
    private fun deliver(result: SecretPickerResult) {
        _result.tryEmit(result)
    }

    private fun endSession() {
        loadJob?.cancel()
        loadJob = null
        loadedEntries = emptyList()
        _rows.value = emptyList()
        _query.value = ""
        _visible.value = false
    }

    private fun publishRows() {
        val query = _query.value.trim()
        _rows.value = loadedEntries
            .filter {
                query.isEmpty() ||
                    it.entryName.contains(query, ignoreCase = true) ||
                    it.username.contains(query, ignoreCase = true)
            }
            .map { SecretPickerRow(uuid = it.uuid, entryName = it.entryName, username = it.username) }
    }
}
