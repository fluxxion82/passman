package ai.passman.viewmodel.pgp.keys

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.DeletePgpKey
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.DeleteSuccess
import ai.passman.viewvo.navigation.PgpDeleteKeyNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class DeleteKeyViewModel(
    private val keyId: Long,
    private val deletePgpKey: DeletePgpKey,
): BaseViewModel() {
    val navigation = Channel<PgpDeleteKeyNavigation>(Channel.RENDEZVOUS)
    val isError = MutableStateFlow(false)
    val errorMessage = MutableStateFlow("")

    fun onConfirmDeleteClick() {
        viewModelScope.launch {
            val outcome = deletePgpKey(keyId)

            if (outcome.isSuccessful()) {
                navigation.send(DeleteSuccess)
            } else {
                errorMessage.emit(outcome.message)
            }
        }
    }

    fun onCancelClick() {
        viewModelScope.launch {
            navigation.send(Back)
        }
    }
}
