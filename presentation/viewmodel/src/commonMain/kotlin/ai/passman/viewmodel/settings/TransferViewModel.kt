package ai.passman.viewmodel.settings

import ai.passman.logging.KLogger
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.StartTransferServer
import ai.passman.domain.settings.TransferFile
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.Reconcile
import ai.passman.viewvo.navigation.TransferNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

open class TransferViewModel(
    private val transferFile: TransferFile,
    private val getIpAddress: GetIpAddress,
    private val startTransferServer: StartTransferServer,
    private val getSyncTargets: GetSyncTargets,
    private val transferEventPersistence: TransferEventPersistence,
): BaseViewModel() {
    val navigation = Channel<TransferNavigation>(Channel.RENDEZVOUS)
    val isReceiving = MutableStateFlow<Boolean?>(null)
    val receivingIpAddress = MutableStateFlow("")
    val inputAddress = MutableStateFlow("")
    val transferError = MutableStateFlow("")

    init {
        viewModelScope.launch {
            transferEventPersistence.events().collect { event ->
                when (event) {
                    is TransferEvent.PassFileReceived -> if (event.conflict) {
                        navigation.send(Reconcile)
                    }
                    TransferEvent.PgpKeysReceived -> Unit
                    TransferEvent.KeystoreReceived -> Unit
                }
            }
        }
        viewModelScope.launch {
            inputAddress.value = getSyncTargets().firstOrNull()?.lastHost.orEmpty()
        }
    }
    fun onReceiveClick() {
        viewModelScope.launch {
            isReceiving.emit(true)
            val ipAddress = getIpAddress()
            receivingIpAddress.emit(ipAddress)
            startTransferServer()
        }
    }

    fun onSendClick() {
        viewModelScope.launch {
            isReceiving.emit(false)
        }
    }

    fun onInputAddressChanged(address: String) {
        viewModelScope.launch {
            inputAddress.emit(address)
        }
    }

    fun onTransferClick() {
        viewModelScope.launch {
            transferError.emit("")
            val outcome = transferFile(inputAddress.value)
            KLogger.i { "transfer file outcome: $outcome" }
            if (outcome.isSuccessful()) {
                navigation.send(Back)
            } else {
                transferError.emit(outcome.message)
            }
        }
    }
}
