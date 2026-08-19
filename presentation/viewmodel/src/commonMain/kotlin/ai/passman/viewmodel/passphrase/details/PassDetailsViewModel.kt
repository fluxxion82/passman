package ai.passman.viewmodel.passphrase.details

import ai.passman.logging.KLogger
import ai.passman.domain.password.DecodeTotpQrImage
import ai.passman.domain.password.DeletePassword
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.GetPassword
import ai.passman.domain.password.UpdatePassword
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.EntryActivity
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.totp.TotpConfig
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.viewmodel.passphrase.PasswordViewModel
import ai.passman.viewvo.passphrase.Back
import ai.passman.viewvo.passphrase.Copied
import ai.passman.viewvo.passphrase.PassphraseNavigation
import ai.passman.viewvo.passphrase.ShowMessage
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * [passwordUuid] is `PasswordEntry.uuid`. Addressing the entry by its display ordinal would let a
 * renumbering read between navigation and save point the edit or the delete at a different
 * credential.
 */
open class PassDetailsViewModel(
    private val passwordUuid: String,
    private val getPassword: GetPassword,
    private val updatePassword: UpdatePassword,
    private val deletePassword: DeletePassword,
    private val copyToClipboard: CopyToClipboard,
    private val generateTotpCode: GenerateTotpCode,
    private val decodeTotpQrImage: DecodeTotpQrImage,
) : PasswordViewModel() {
    val navigation = Channel<PassphraseNavigation>()

    val entryName = MutableStateFlow("")
    val userName = MutableStateFlow("")
    val website = MutableStateFlow("")
    val notes = MutableStateFlow("")
    val totpSeed = MutableStateFlow("")
    val customFields = MutableStateFlow<List<CustomField>>(emptyList())

    /** When this entry was actually first created. See [PasswordEntry.createdAt]. */
    val createdAt = MutableStateFlow(0L)

    /**
     * [PasswordEntry.dateCreated] despite its name: it is overwritten on every edit and is what
     * the rest of the app already treats as "last edited" (see that field's KDoc).
     */
    val lastEditedAt = MutableStateFlow(0L)

    /**
     * This entry's history, oldest-first as stored (`mergeActivity` sorts ascending and depends on
     * that order). Reverse only where it is displayed, never here.
     */
    val activity = MutableStateFlow<List<EntryActivity>>(emptyList())

    /**
     * The code valid right now, or null when the entry has no (valid) seed. The ticker only runs
     * while something collects — leaving the screen stops it.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    val totpCode: StateFlow<GenerateTotpCode.TotpCode?> = totpSeed
        .flatMapLatest { seed ->
            if (seed.isBlank()) {
                flowOf<GenerateTotpCode.TotpCode?>(null)
            } else {
                flow {
                    while (true) {
                        emit(generateTotpCode(seed.trim()))
                        delay(1_000)
                    }
                }
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(), null)

    var editMode = MutableStateFlow(false)

    /** A double-tapped save would send Back twice and pop an extra screen off the stack. */
    val isSaving = MutableStateFlow(false)

    private var passwordEntry: PasswordEntry? = null

    init {
        KLogger.d {
            "pass uuid: $passwordUuid"
        }
        viewModelScope.launch {
            val entry = getPassword(passwordUuid)
            if (entry != null) {
                passwordEntry = entry
                entryName.emit(entry.entryName)
                userName.emit(entry.username)
                password.emit(entry.password)
                website.emit(entry.website)
                notes.emit(entry.notes)
                totpSeed.emit(entry.totpSeed)
                customFields.emit(entry.customFields)
                createdAt.emit(entry.createdAt)
                lastEditedAt.emit(entry.dateCreated)
                activity.emit(entry.activity)
            } else {
                // we have problems
                KLogger.d {
                    "no pass found"
                }
            }
        }
    }

    fun onEntryNameChanged(entry: String) {
        viewModelScope.launch { entryName.emit(entry) }
    }

    fun onUserNameChanged(userName: String) {
        viewModelScope.launch { this@PassDetailsViewModel.userName.emit(userName) }
    }

    fun onWebsiteChanged(site: String) {
        viewModelScope.launch { website.emit(site) }
    }

    fun onNotesChanged(notes: String) {
        viewModelScope.launch { this@PassDetailsViewModel.notes.emit(notes) }
    }

    fun onTotpSeedChanged(seed: String) {
        viewModelScope.launch { totpSeed.emit(seed) }
    }

    fun onQrScanned(payload: String) {
        viewModelScope.launch {
            val seed = TotpConfig.normalizeSeed(payload)
            if (seed != null) {
                totpSeed.emit(seed)
            } else {
                navigation.send(ShowMessage("That QR code is not a TOTP setup code"))
            }
        }
    }

    fun onQrImagePicked(path: String) {
        KLogger.d { "qr image picked: $path" }
        viewModelScope.launch {
            when (val result = decodeTotpQrImage(path)) {
                is DecodeTotpQrImage.Result.Seed -> totpSeed.emit(result.seed)
                DecodeTotpQrImage.Result.NoQrFound ->
                    navigation.send(ShowMessage("No QR code found in that image"))
                DecodeTotpQrImage.Result.NotTotp ->
                    navigation.send(ShowMessage("That QR code is not a TOTP setup code"))
                DecodeTotpQrImage.Result.UnreadableImage ->
                    navigation.send(ShowMessage("Couldn't read that image file — try a PNG or JPEG"))
            }
        }
    }

    fun onAddCustomField() {
        customFields.value += CustomField(label = "", value = "")
    }

    fun onCustomFieldLabelChanged(index: Int, label: String) {
        updateCustomField(index) { it.copy(label = label) }
    }

    fun onCustomFieldValueChanged(index: Int, value: String) {
        updateCustomField(index) { it.copy(value = value) }
    }

    fun onCustomFieldSecretToggled(index: Int) {
        updateCustomField(index) { it.copy(secret = !it.secret) }
    }

    fun onRemoveCustomField(index: Int) {
        customFields.value = customFields.value.filterIndexed { i, _ -> i != index }
    }

    fun onCustomFieldCopyClicked(index: Int) {
        val field = customFields.value.getOrNull(index) ?: return
        viewModelScope.launch {
            copyToClipboard(field.value)
            navigation.send(Copied)
        }
    }

    private fun updateCustomField(index: Int, transform: (CustomField) -> CustomField) {
        customFields.value = customFields.value.mapIndexed { i, field ->
            if (i == index) transform(field) else field
        }
    }

    fun onSaveClick() {
        KLogger.d {
            "save clicked"
        }
        if (isSaving.value) return
        isSaving.value = true
        viewModelScope.launch {
            val entry = passwordEntry ?: run {
                isSaving.value = false
                return@launch
            }
            val seed = totpSeed.value.trim()
            if (seed.isNotEmpty() && generateTotpCode(seed) == null) {
                KLogger.e { "rejecting save: unparseable totp seed" }
                isSaving.value = false
                return@launch
            }
            // copy() rather than a fresh PasswordEntry: the identity has to come along untouched,
            // and a constructor call is one added field away from silently dropping it.
            val saved = updatePassword.invoke(
                entry.copy(
                    entryName = entryName.value,
                    username = userName.value,
                    password = password.value,
                    website = website.value,
                    notes = notes.value,
                    totpSeed = seed,
                    customFields = customFields.value.filterNot { it.label.isBlank() && it.value.isBlank() },
                )
            )
            // Navigating away is this screen's success signal: leaving on a failed save tells the
            // user their edit landed when the repository just reported that it did not.
            if (saved) {
                // No re-read of the history here. `updatePassword` appends the edit record inside the
                // repository, so this ViewModel's copies do go stale — but Back is sent immediately
                // below and the only handler pops the screen, so nothing rendered from them is ever
                // seen again. Re-reading would cost a full vault decrypt, plus a second seal-and-write
                // whenever the save renamed the entry and changed the sort order, all of it before
                // navigation is even sent (`send` on a rendezvous channel suspends until it lands).
                // Reopening the entry fetches it fresh.
                // Flag stays up: Back is on its way and a freed button would double-pop the stack.
                navigation.send(Back)
            } else {
                isSaving.value = false
                KLogger.e { "save failed for $passwordUuid - staying on the screen" }
            }
        }
    }

    fun onUsernameCopyClicked() {
        KLogger.d {
            "username copy clicked"
        }
        viewModelScope.launch {
            copyToClipboard(userName.value)
            navigation.send(Copied)
        }
    }

    fun onPasswordCopyClicked() {
        KLogger.d {
            "password copy clicked"
        }
        viewModelScope.launch {
            copyToClipboard(password.value)
            navigation.send(Copied)
        }
    }

    fun onTotpCopyClicked() {
        val code = totpCode.value?.code ?: return
        viewModelScope.launch {
            copyToClipboard(code)
            navigation.send(Copied)
        }
    }

    fun onEditClicked() {
        editMode.value = !editMode.value
    }

    fun onDeleteClicked() {
        KLogger.d {
            "delete clicked"
        }
        viewModelScope.launch {
            if (deletePassword(passwordUuid)) {
                navigation.send(Back)
            } else {
                KLogger.e { "delete failed for $passwordUuid - staying on the screen" }
            }
        }
    }
}
