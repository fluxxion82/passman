package ai.passman.viewmodel.base

//import androidx.lifecycle.ViewModel
//import cafe.adriel.voyager.core.model.ScreenModel
//import kotlinx.coroutines.cancel

//actual abstract class BaseViewModel: ViewModel() {
//    actual val presenterScope: ViewModelScope = ViewModelScopeImpl(this)
//
//    actual open fun onClear() {
//        println("on clear")
//        onCleared()
//        presenterScope.coroutineContext.cancel()
//    }
//
//    override fun onCleared() {
//        println("${this::class} on cleared")
//    }
//}
