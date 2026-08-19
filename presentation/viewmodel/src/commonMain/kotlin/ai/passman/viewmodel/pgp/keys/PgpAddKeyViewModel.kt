package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.password.AddPassword
import ai.passman.domain.pgp.CreatePgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.ErrorMessage
import ai.passman.viewvo.navigation.PgpCreateKeyNavigation
import ai.passman.viewmodel.passphrase.PasswordViewModel
import androidx.lifecycle.viewModelScope
import kotlin.time.Duration.Companion.days
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.number
import kotlinx.datetime.toLocalDateTime

class PgpAddKeyViewModel(
    private val createPgpKey: CreatePgpKeyPair,
    private val addPassword: AddPassword,
): PasswordViewModel() {
    val navigation = Channel<PgpCreateKeyNavigation>(Channel.RENDEZVOUS)
    val nameState = MutableStateFlow("")
    val emailState = MutableStateFlow("")
    val currentAlgorithm = MutableStateFlow(PgpKeyAlgorithm.RSA_ENCRYPT)
    val dateState = MutableStateFlow("")
    val lengthOptions = MutableStateFlow(listOf("4096", "3072", "2048"))
    val lengthState = MutableStateFlow("4096")
    val isLoading = MutableStateFlow(false)

    val isExpirationChecked = MutableStateFlow(false)
    val isSavePassToListChecked = MutableStateFlow(false)

    private var dateMillis: Long = 0L

    init {
        val now = Clock.System.now()
        val nextYear = now.plus(365.days)
        dateMillis = nextYear.toEpochMilliseconds()

        viewModelScope.launch {
            dateState.emit(formatInstant(nextYear))
        }
    }

    fun onDateSelected(date: Long) {
        viewModelScope.launch {
            dateMillis = date
            dateState.emit(formatInstant(Instant.fromEpochMilliseconds(dateMillis)))
        }
    }

    private fun formatInstant(instant: Instant): String {
        // Convert the Instant to a LocalDateTime using the system default time zone
        val localDateTime = instant.toLocalDateTime(TimeZone.currentSystemDefault())
        val localDate = localDateTime.date

        // Extract the day, month, and year
        val day = localDate.day
        val month = localDate.month.number
        val year = localDate.year

        // Manually format the date using the pattern
        return "dd/MM/yyyy"
            .replace("dd", day.toString().padStart(2, '0'))
            .replace("MM", month.toString().padStart(2, '0'))
            .replace("yyyy", year.toString())
    }

    fun onAlgorithmSelected(algorithm: PgpKeyAlgorithm) {
        viewModelScope.launch {
            currentAlgorithm.emit(algorithm)
            when(algorithm) {
                PgpKeyAlgorithm.DSA_SIGN -> lengthOptions.emit(dsaLengths) // can't be reached atm
                PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> lengthOptions.emit(dsaLengths)
                PgpKeyAlgorithm.RSA_SIGN,
                PgpKeyAlgorithm.RSA_ENCRYPT -> lengthOptions.emit(rsaLengths)
                PgpKeyAlgorithm.ED25519 -> lengthOptions.emit(listOf("256"))
            }

            lengthState.emit(lengthOptions.value.first())
        }
    }

    fun onNameChange(name: String) {
        viewModelScope.launch {
            nameState.emit(name)
        }
    }

    fun onEmailChange(email: String) {
        viewModelScope.launch {
            emailState.emit(email)
        }
    }

    fun onLengthSelected(length: String) {
        viewModelScope.launch {
            lengthState.emit(length)
        }
    }

    fun onExpirationEnabled(isChecked: Boolean) {
        viewModelScope.launch {
            isExpirationChecked.emit(isChecked)
        }
    }

    fun onSavePasswordClicked(isChecked: Boolean) {
        viewModelScope.launch {
            isSavePassToListChecked.emit(isChecked)
        }
    }

    fun onCreateSubkeyClick() {
        // Synchronous guard: the flag used to flip inside the coroutine, which left a race
        // window before it ran — the widest one in the app, since RSA-4096 keygen takes seconds.
        if (isLoading.value) return
        isLoading.value = true
        viewModelScope.launch {
            val outcome = createPgpKey(
                param = CreatePgpKeyPair.CreatePgpKey(
                    name = nameState.value,
                    email = emailState.value,
                    length = lengthState.value.toInt(),
                    algorithm = currentAlgorithm.value,
                    expirationSeconds = if (isExpirationChecked.value) {
                        ((dateMillis - Clock.System.now().toEpochMilliseconds()) / 1000).coerceAtLeast(0L)
                    } else 0L,
                    password = password.value,
                )
            )

            if (outcome.isSuccessful()) {
                if (isSavePassToListChecked.value) {
                    addPassword(
                        AddPassword.EntryData(
                            entryName = "${nameState.value} PGP Key",
                            userName = emailState.value,
                            password = password.value,
                            website = "",
                            notes = "",
                        )
                    )
                }

                navigation.send(Back)
            } else {
                navigation.send(ErrorMessage(outcome.message))
            }

            isLoading.emit(false)
        }
    }
}
