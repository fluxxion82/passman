package ai.passman.viewmodel.pgp.userid.remove

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.GetPgpKey
import ai.passman.domain.pgp.UpdateUserId
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.UserId
import ai.passman.domain.pgp.model.UserIdAction
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.PgpAddUserIdNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class RemoveUserIdViewModel(
    val keyId: Long,
    val userId: String,
    val userIdAction: UserIdAction,
    private val getPgpKey: GetPgpKey,
    private val updateUserId: UpdateUserId,
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

    fun onRemoveClick() {
        viewModelScope.launch {
            val key = pgpKey.value ?: return@launch
            val outcome = updateUserId(
                UpdateUserId.UpdateUserIdRequest(
                    keyPair = key,
                    password = passwordState.value,
                    userId = UserId.processUserId(userId, false),
                    userIdAction = userIdAction,
                )
            )

            if (outcome.isSuccessful()) {
                navigation.send(Back)
            }
        }
    }
}
