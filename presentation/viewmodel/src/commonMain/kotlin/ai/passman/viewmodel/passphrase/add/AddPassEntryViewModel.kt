package ai.passman.viewmodel.passphrase.add

import ai.passman.logging.KLogger
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.DecodeTotpQrImage
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.totp.TotpConfig
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.viewvo.navigation.AddPasswordNavigation
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.InvalidEntry
import ai.passman.viewmodel.passphrase.PasswordViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

const val STARTING_STRING_LENGTH = 10

open class AddPassEntryViewModel(
    private val addPassword: AddPassword,
    private val passwordEventPersistence: PasswordEventPersistence,
    private val generateTotpCode: GenerateTotpCode,
    private val decodeTotpQrImage: DecodeTotpQrImage,
) : PasswordViewModel() {
    val navigation = Channel<AddPasswordNavigation>(Channel.RENDEZVOUS)
    val entryName = MutableStateFlow("")
    val userName = MutableStateFlow("")
    val website = MutableStateFlow("")
    val notes = MutableStateFlow("")
    val totpSeed = MutableStateFlow("")
    val customFields = MutableStateFlow<List<CustomField>>(emptyList())

    /** Every addPassword call mints a fresh uuid, so a double-tap would mint a duplicate entry. */
    val isSaving = MutableStateFlow(false)

    init {
        KLogger.d { "instance created" }
        viewModelScope.launch {
            passwordEventPersistence.events().collect { event ->
                when (event) {
                    PasswordEvent.Created -> navigation.send(Back)
                    else -> Unit
                }
            }
        }
    }

    fun onEntryNameChanged(entry: String) {
        viewModelScope.launch { entryName.emit(entry) }
    }

    fun onUserNameChanged(userName: String) {
        viewModelScope.launch { this@AddPassEntryViewModel.userName.emit(userName) }
    }

    fun onWebsiteChanged(site: String) {
        viewModelScope.launch { website.emit(site) }
    }

    fun onNotesChanged(notes: String) {
        viewModelScope.launch { this@AddPassEntryViewModel.notes.emit(notes) }
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
                navigation.send(InvalidEntry("That QR code is not a TOTP setup code"))
            }
        }
    }

    fun onQrImagePicked(path: String) {
        KLogger.d { "qr image picked: $path" }
        viewModelScope.launch {
            when (val result = decodeTotpQrImage(path)) {
                is DecodeTotpQrImage.Result.Seed -> totpSeed.emit(result.seed)
                DecodeTotpQrImage.Result.NoQrFound ->
                    navigation.send(InvalidEntry("No QR code found in that image"))
                DecodeTotpQrImage.Result.NotTotp ->
                    navigation.send(InvalidEntry("That QR code is not a TOTP setup code"))
                DecodeTotpQrImage.Result.UnreadableImage ->
                    navigation.send(InvalidEntry("Couldn't read that image file — try a PNG or JPEG"))
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

    private fun updateCustomField(index: Int, transform: (CustomField) -> CustomField) {
        customFields.value = customFields.value.mapIndexed { i, field ->
            if (i == index) transform(field) else field
        }
    }

    fun onSaveClick() {
        if (isSaving.value) return
        isSaving.value = true
        viewModelScope.launch {
            val seed = totpSeed.value.trim()
            if (seed.isNotEmpty() && generateTotpCode(seed) == null) {
                isSaving.value = false
                navigation.send(InvalidEntry("The TOTP seed is not a valid base32 secret or otpauth link"))
                return@launch
            }
            val saved = addPassword.invoke(
                AddPassword.EntryData(
                    entryName = entryName.value,
                    userName = userName.value,
                    password = password.value,
                    website = website.value,
                    notes = notes.value,
                    totpSeed = seed,
                    customFields = customFields.value.filterNot { it.label.isBlank() && it.value.isBlank() },
                )
            )
            // On success the flag stays up: PasswordEvent.Created is about to navigate away, and
            // freeing the button first would reopen the duplicate-entry window.
            if (!saved) isSaving.value = false
        }
    }
}
