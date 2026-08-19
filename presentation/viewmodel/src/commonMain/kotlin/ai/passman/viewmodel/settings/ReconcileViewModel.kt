package ai.passman.viewmodel.settings

import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.settings.ExecuteReconcileAction
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.ReconcileNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class ReconcileViewModel(
    private val executeReconcileAction: ExecuteReconcileAction,
): BaseViewModel() {
    val navigation = Channel<ReconcileNavigation>(Channel.RENDEZVOUS)
    val reconcileError = MutableStateFlow("")

    fun onMergeClicked() {
        executeAction(ReconcileAction.Merge)
    }

    fun onOverwriteClicked() {
        executeAction(ReconcileAction.Overwrite)
    }

    fun onDeleteClicked() {
        executeAction(ReconcileAction.Delete)
    }

    private fun executeAction(action: ReconcileAction) {
        viewModelScope.launch {
            reconcileError.emit("")
            val outcome = executeReconcileAction(action)
            if (outcome.isSuccessful()) {
                navigation.send(Back)
            } else {
                reconcileError.emit(outcome.message)
            }
        }
    }
}
