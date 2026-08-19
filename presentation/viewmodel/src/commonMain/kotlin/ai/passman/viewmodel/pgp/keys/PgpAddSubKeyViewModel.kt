package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.AddSubKey
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.ErrorMessage
import ai.passman.viewvo.navigation.PgpAddSubkeyNavigation
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

val rsaLengths = listOf("4096", "3072", "2048")
val dsaLengths = listOf("3072", "2048", "1024")
val elgamalLengths = listOf("256", "3072",)

class PgpAddSubKeyViewModel(
    private val keyId: Long,
    private val getPgpKey: GetPgpKey,
    private val addSubKey: AddSubKey,
): BaseViewModel() {
    val navigation = Channel<PgpAddSubkeyNavigation>()
    val currentAlgorithm = MutableStateFlow(PgpKeyAlgorithm.RSA_ENCRYPT)
    val dateState = MutableStateFlow("")
    val lengthOptions = MutableStateFlow(listOf("4096", "3072", "2048"))
    val lengthState = MutableStateFlow("4096")
    val passwordState = MutableStateFlow("")
    val isLoading = MutableStateFlow(false)
    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)
    var expirationSet = MutableStateFlow(false)

    private var dateMillis: Long = 0L

    init {
        val now = Clock.System.now()
        val nextYear = now.plus(365.days)
        dateMillis = nextYear.toEpochMilliseconds()

        viewModelScope.launch {
            dateState.emit(formatInstant(nextYear))

            pgpKey.emit(getPgpKey(keyId))
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
                PgpKeyAlgorithm.DSA_SIGN -> lengthOptions.emit(dsaLengths)
                PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> lengthOptions.emit(rsaLengths)
                PgpKeyAlgorithm.RSA_SIGN,
                PgpKeyAlgorithm.RSA_ENCRYPT -> lengthOptions.emit(rsaLengths)
                PgpKeyAlgorithm.ED25519 -> lengthOptions.emit(listOf("256"))
            }

            lengthState.emit(lengthOptions.value.first())
        }
    }

    fun onLengthSelected(length: String) {
        viewModelScope.launch {
            lengthState.emit(length)
        }
    }

    fun onPasswordChanged(password: String) {
        viewModelScope.launch {
            passwordState.emit(password)
        }
    }

    fun onExpirationEnabled(isChecked: Boolean) {
        viewModelScope.launch {
            expirationSet.emit(isChecked)
        }
    }

    fun onCreateSubkeyClick() {
        viewModelScope.launch {
            val key = pgpKey.value ?: return@launch
            isLoading.emit(true)
            val outcome = addSubKey(
                param = AddSubKey.AddSubKeyRequest(
                    keyPair = key,
                    password = passwordState.value,
                    length = lengthState.value.toInt(),
                    algorithm = currentAlgorithm.value,
                    expirationSeconds = if (expirationSet.value) {
                        ((dateMillis - Clock.System.now().toEpochMilliseconds()) / 1000).coerceAtLeast(0L)
                    } else 0L,
                )
            )

            if (outcome.isSuccessful()) {
                navigation.send(Back)
            } else {
                navigation.send(ErrorMessage(outcome.message))
            }

            isLoading.emit(false)
        }
    }
}
