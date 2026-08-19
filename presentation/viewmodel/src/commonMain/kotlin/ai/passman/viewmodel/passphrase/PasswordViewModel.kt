package ai.passman.viewmodel.passphrase

import ai.passman.domain.user.GeneratePassword
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewmodel.passphrase.add.STARTING_STRING_LENGTH
import androidx.lifecycle.viewModelScope
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The regenerate button behind every password field's refresh icon.
 *
 * Generation goes through the [GeneratePassword] use case — the CSPRNG-backed generator — rather
 * than a local `kotlin.random` pool: these strings become real credentials the moment the user
 * saves the form, and the previous hand-rolled pool was both predictable (plain `Random`) and
 * skewed (duplicated ranges). The screens offer no charset options, so all four sets are used.
 * The default instance keeps the five subclasses' constructors unchanged; the use case is
 * stateless and dependency-free, so the default is identical to the DI-registered one.
 */
@OptIn(ExperimentalAtomicApi::class)
open class PasswordViewModel(
    private val generatePassword: GeneratePassword = GeneratePassword(),
) : BaseViewModel() {
    val password = MutableStateFlow("")
    private val clickCount = AtomicInt(0)

    fun onReGenPass() {
        viewModelScope.launch {
            val curSize = password.value.length
            val calSize = (if (clickCount.load() == 0 && curSize == 0) STARTING_STRING_LENGTH else curSize) + clickCount.load()
            val passSize = if (curSize in 1..< calSize - 1) {
                clickCount.store(0)
                curSize
            } else {
                calSize
            }
            val generated = generatePassword(
                GeneratePassword.PasswordInfo(
                    charSet = setOf(
                        GeneratePassword.CharSet.UPPERCASE,
                        GeneratePassword.CharSet.LOWERCASE,
                        GeneratePassword.CharSet.NUMBER,
                        GeneratePassword.CharSet.SYMBOLS,
                    ),
                    passLength = passSize,
                ),
            )
            clickCount.addAndFetch(1)
            // Never log the generated value — it is a credential the moment the user keeps it.
            password.emit(generated)
        }
    }

    fun onPasswordChanged(pass: String) {
        viewModelScope.launch { password.emit(pass) }
    }
}
