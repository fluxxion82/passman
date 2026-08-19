package ai.passman.viewmodel.home

import ai.passman.logging.KLogger
import ai.passman.domain.keystore.ImportKeystore
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.ImportPgpKey
import ai.passman.domain.user.LogoutUser
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.home.HomeNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch

class HomeViewModel(
    private val importPgpKeys: ImportPgpKey,
    private val importKeystore: ImportKeystore,
    private val logoutUser: LogoutUser,
) : BaseViewModel() {
    val navigation = Channel<HomeNavigation>(Channel.RENDEZVOUS)
    val userMessages = Channel<String>(Channel.BUFFERED)

    fun onPasswordManagement() =
        viewModelScope.launch { navigation.send(HomeNavigation.PasswordManagement) }

    fun onKeystoreClick() =
        viewModelScope.launch { navigation.send(HomeNavigation.KeystoreTools) }

    fun onPgpClick() =
        viewModelScope.launch { navigation.send(HomeNavigation.PgpTools) }

    fun onSettingsClick() =
        viewModelScope.launch { navigation.send(HomeNavigation.Settings) }

    fun onLogoutClick() {
        KLogger.d { "logout" }
        viewModelScope.launch {
            logoutUser(true)
            navigation.send(HomeNavigation.Logout)
        }
    }

    fun importFile(actionType: Int, selectedFile: String) {
        viewModelScope.launch {
            when (actionType) {
                1 -> when (val outcome = importPgpKeys(selectedFile)) {
                    is Outcome.Success -> Unit
                    is Outcome.Error -> userMessages.send(outcome.message)
                }
                2 -> when (val outcome = importKeystore(selectedFile)) {
                    is Outcome.Success -> Unit
                    is Outcome.Error -> userMessages.send(outcome.message)
                }
            }
        }
    }

    fun onActionClick(actionType: Int) {
        viewModelScope.launch {
            when (actionType) {
                0 -> navigation.send(HomeNavigation.AddPass)
                1 -> navigation.send(HomeNavigation.AddPgpKey)
                2 -> navigation.send(HomeNavigation.AddKeystore)
                else -> error("not supported")
            }
        }
    }
}
