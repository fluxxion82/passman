package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.ModifySubKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.PgpAddUserIdNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class ModifyPgpSubkeyViewModel(
    val keyId: Long,
    val subkeyId: String,
    val action: SubKeyAction,
    private val getPgpKey: GetPgpKey,
    private val modifySubKey: ModifySubKey,
): BaseViewModel() {
    val navigation = Channel<PgpAddUserIdNavigation>(Channel.RENDEZVOUS)

    val passwordState = MutableStateFlow("")
    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)

    init {
        viewModelScope.launch {
            pgpKey.emit(getPgpKey(keyId))
        }
    }

    fun onPasswordChange(password: String) {
        viewModelScope.launch {
            passwordState.emit(password)
        }
    }

    fun onActionClick() {
        viewModelScope.launch {
            val key = pgpKey.value ?: return@launch
            val outcome = modifySubKey(
                ModifySubKey.ModifySubkeyRequest(
                    keyPair = key,
                    password = passwordState.value,
                    subKeyId = subkeyId,
                    action = action,
                )
            )

            if (outcome.isSuccessful()) {
                navigation.send(Back)
            }
        }
    }
}
