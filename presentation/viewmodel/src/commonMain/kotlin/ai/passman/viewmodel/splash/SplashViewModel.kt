package ai.passman.viewmodel.splash

import ai.passman.logging.KLogger
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.splash.SplashNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

open class SplashViewModel : BaseViewModel() {
    val navigation = Channel<SplashNavigation>(Channel.RENDEZVOUS)

    fun onLoginClicked() {
        KLogger.d { "onLoginClicked" }
        viewModelScope.launch {
            navigation.send(SplashNavigation.Login)
        }
    }

    fun onSignUpClicked() {
        viewModelScope.launch {
            navigation.send(SplashNavigation.SignUp)
        }
    }
}
