package ai.passman.viewmodel.pgp.userid.add

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

class AddUserIdViewModel(
    private val keyId: Long,
    private val getPgpKey: GetPgpKey,
    private val updateUserId: UpdateUserId,
): BaseViewModel() {
    val navigation = Channel<PgpAddUserIdNavigation>(Channel.RENDEZVOUS)
    val nameState = MutableStateFlow("")
    val emailState = MutableStateFlow("")
    val passwordState = MutableStateFlow("")
    val pgpKey = MutableStateFlow<PgpKeyPair?>(null)
    val isError = MutableStateFlow(false)
    val errorMessage = MutableStateFlow("")

    init {
        viewModelScope.launch {
            pgpKey.emit(getPgpKey(keyId))
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

    fun onPasswordChange(password: String) {
        viewModelScope.launch {
            passwordState.emit(password)
        }
    }

    fun onCreateClick() {
        val key = pgpKey.value ?: return
        if (key.publicKey.userIds.any { it.email == emailState.value }) {
            errorMessage.value = "A user ID with this email already exists"
            isError.value = true
            return
        }

        viewModelScope.launch {
            val outcome = updateUserId(
                UpdateUserId.UpdateUserIdRequest(
                    keyPair = key,
                    password = passwordState.value,
                    userId = UserId(
                        name = nameState.value,
                        email = emailState.value,
                        isRevoked = false,
                    ),
                    userIdAction = UserIdAction.ADD,
                )
            )

            if (outcome.isSuccessful()) {
                navigation.send(Back)
            } else {
                errorMessage.emit(outcome.message)
                isError.emit(true)
            }
        }
    }
}
