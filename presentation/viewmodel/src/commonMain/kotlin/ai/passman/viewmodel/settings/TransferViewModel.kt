package ai.passman.viewmodel.settings

import ai.passman.logging.KLogger
import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.StartTransferServer
import ai.passman.domain.settings.StopTransferServer
import ai.passman.domain.settings.TransferFile
import ai.passman.domain.settings.model.TransferEvent
import ai.passman.domain.settings.persistence.TransferEventPersistence
import ai.passman.viewmodel.base.BaseViewModel
import ai.passman.viewvo.navigation.Back
import ai.passman.viewvo.navigation.Reconcile
import ai.passman.viewvo.navigation.TransferNavigation
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

open class TransferViewModel(
    private val transferFile: TransferFile,
    private val getIpAddress: GetIpAddress,
    private val startTransferServer: StartTransferServer,
    private val stopTransferServer: StopTransferServer,
    private val getSyncTargets: GetSyncTargets,
    private val transferEventPersistence: TransferEventPersistence,
    private val teardownScope: CoroutineScope = CoroutineScope(Dispatchers.Default),
): BaseViewModel() {
    val navigation = Channel<TransferNavigation>(Channel.RENDEZVOUS)
    val isReceiving = MutableStateFlow<Boolean?>(null)
    val receivingIpAddress = MutableStateFlow("")
    val inputAddress = MutableStateFlow("")
    val transferError = MutableStateFlow("")

    // The shared transfer server is refcounted (TransferRepository.startTransferServer's KDoc):
    // a lease is held if and only if startTransferServer() returned normally. Tracked here so
    // onCleared() below releases at most the lease this screen actually took - never one it never
    // held (a bind failure below never sets this), and never twice.
    private var holdingLease = false

    // Tracks onReceiveClick's own launch so a second tap while the first is still starting can be
    // dropped instead of taking a second lease - see onReceiveClick's KDoc. Also joined from
    // onCleared() below so its release check reads holdingLease's final value rather than a value
    // that is still in flight.
    private var receiveJob: Job? = null

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
    /**
     * `startTransferServer()` now throws on a failed bind instead of swallowing it (see its
     * KDoc), so a leftover lease from a previous session or another sync in flight - anything
     * still holding port 2323 - would otherwise crash the app here with no catch anywhere above
     * this call. Same treatment as `runSyncSession`: catch, surface as an error, never propagate.
     *
     * Guarded by [receiveJob] against a second tap: the button stays live until `isReceiving`
     * recomposes through the screen's `AnimatedContent`, and that state flip only happens inside
     * the coroutine below, not synchronously on click. Without the guard, two taps before that
     * recomposition each take out their own lease; `holdingLease` is a plain Boolean, so
     * `onCleared()` only ever releases one of the two, and the other pins the shared mTLS server
     * on port 2323 for the rest of the process - there is no unconditional stop anywhere to mop it
     * up once the server is refcounted. `receiveJob?.isActive` reads true the instant
     * `viewModelScope.launch` returns, before the launched body has run a single line, because a
     * `Job` is created eagerly - so the second tap's check is not a race with the first tap's own
     * coroutine the way a flag set from inside that coroutine would be (`TrustedDevicesViewModel
     * .onBeginPairingClick` guards its own ceremony launch the same way).
     */
    fun onReceiveClick() {
        if (receiveJob?.isActive == true) return
        receiveJob = viewModelScope.launch {
            isReceiving.emit(true)
            val ipAddress = getIpAddress()
            receivingIpAddress.emit(ipAddress)
            try {
                // NonCancellable for the same reason runSyncSession wraps its own
                // startTransferServer() call: withContext still checks ensureActive() on the way
                // back out of its block, so a cancellation landing here - viewModelScope tearing
                // down mid-bind - could let the bind finish (lease taken) and then throw before
                // `holdingLease = true` ever runs. That would read as "never held a lease" to
                // onCleared() below, for a screen that actually holds one - a permanent leak, the
                // same shape a plain (non-NonCancellable) stopTransferServer would leak on the
                // teardown side.
                withContext(NonCancellable) {
                    startTransferServer()
                    holdingLease = true
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                KLogger.e(e) { "transfer server failed to start" }
                isReceiving.emit(null)
                transferError.emit(e.message ?: "Failed to start the receive server")
            }
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

    /**
     * Releases the lease [onReceiveClick] took out, if any. Without this the refcounted server
     * pins itself for the rest of the process's life the first time anyone visits Receive mode:
     * under the old unrefcounted server the next sync session's unconditional stop mopped up
     * whatever a screen forgot to release, but the refcount takes that safety net away - every
     * future `stopTransferServer()` call just decrements a count that never returns to zero, and
     * the socket stays bound long after this screen is gone.
     *
     * `viewModelScope` is already cancelled by the time `onCleared()` runs (it is closed before
     * this callback fires), so the release has to run on an independent scope - the same pattern
     * `TrustedDevicesViewModel.onCleared` uses for its own out-of-band teardown.
     *
     * Joins [receiveJob] before reading [holdingLease], on that same independent scope. Without
     * the join this would race [onReceiveClick]'s own `NonCancellable` block: `onCleared()` runs
     * synchronously the moment the store clears, independent of whatever the launched click
     * coroutine is doing, so it could read `holdingLease` before that block finishes setting it.
     * `NonCancellable` is what lets that coroutine keep running at all once `viewModelScope` is
     * cancelled - but nothing makes `onCleared()` wait for it on its own, and reading a flag mid
     * write is exactly the ordering bug the `NonCancellable` wrapper was added to close.
     * `receiveJob.join()` suspends until that coroutine has fully unwound - including its
     * `NonCancellable` segment - so by the time this checks `holdingLease` it is reading the
     * lease's real, final state rather than a value still in flight. A null `receiveJob` (Receive
     * was never tapped) makes the join a no-op.
     */
    override fun onCleared() {
        super.onCleared()
        teardownScope.launch {
            receiveJob?.join()
            if (holdingLease) {
                holdingLease = false
                stopTransferServer()
            }
        }
    }
}
