package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.ChangePgpKeyPassword
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.PgpChangePasswordNavigation

import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class ChangePasswordViewModel(
    val keyId: Long,
    private val getPgpKey: GetPgpKey,
    private val changePassword: ChangePgpKeyPassword,
): BaseViewModel() {
    val navigation = Channel<PgpChangePasswordNavigation>(Channel.RENDEZVOUS)

    val oldPasswordState = MutableStateFlow("")
    val newPasswordState = MutableStateFlow("")

    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)

    init {
        viewModelScope.launch {
            pgpKey.emit(getPgpKey(keyId))
        }
    }

    fun onOldPasswordChange(password: String) {
        viewModelScope.launch {
            oldPasswordState.emit(password)
        }
    }

    fun onNewPasswordChange(password: String) {
        viewModelScope.launch {
            newPasswordState.emit(password)
        }
    }

    fun onActionClick() {
        viewModelScope.launch {
            val key = pgpKey.value ?: return@launch
            val outcome = changePassword(
                ChangePgpKeyPassword.ChangePgpKeyPasswordRequest(
                    keyPair = key,
                    newPassword = newPasswordState.value,
                    oldPassword = oldPasswordState.value,
                )
            )

            if (outcome.isSuccessful()) {
                navigation.send(Back)
            }
        }
    }
}
