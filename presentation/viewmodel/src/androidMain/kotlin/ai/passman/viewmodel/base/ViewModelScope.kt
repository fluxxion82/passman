package ai.passman.viewmodel.base

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlin.coroutines.CoroutineContext

internal class ViewModelScopeImpl(private val viewModel: BaseViewModel) : ViewModelScope {
    override val coroutineContext: CoroutineContext
        get() = (viewModel as ViewModel).viewModelScope.coroutineContext
}
