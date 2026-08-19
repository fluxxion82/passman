package ai.passman.viewmodel.settings

import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.StartTransferServer
import ai.passman.domain.settings.StopTransferServer
import ai.passman.domain.settings.TransferFile
import ai.passman.domain.settings.persistence.TransferEventPersistence
import androidx.lifecycle.ViewModelStore
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * Covers review finding 3 (a double tap of Receive must not take out a second lease) and its
 * teardown-side counterpart (an `onCleared()` that reads the lease flag before the click
 * coroutine's `NonCancellable` start has actually set it). See [TransferViewModel.onReceiveClick]
 * and [TransferViewModel.onCleared] for the reasoning each fix documents.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TransferViewModelTest {
    private val transferFile: TransferFile = mockk(relaxed = true)
    private val getIpAddress: GetIpAddress = mockk(relaxed = true)
    private val startTransferServer: StartTransferServer = mockk(relaxed = true)
    private val stopTransferServer: StopTransferServer = mockk(relaxed = true)
    private val getSyncTargets: GetSyncTargets = mockk(relaxed = true)
    private val transferEventPersistence: TransferEventPersistence = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getSyncTargets.invoke(Unit) } returns emptyList()
        coEvery { getIpAddress.invoke(Unit) } returns "192.168.1.5"
        every { transferEventPersistence.events() } returns emptyFlow()
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = TransferViewModel(
        transferFile = transferFile,
        getIpAddress = getIpAddress,
        startTransferServer = startTransferServer,
        stopTransferServer = stopTransferServer,
        getSyncTargets = getSyncTargets,
        transferEventPersistence = transferEventPersistence,
        teardownScope = CoroutineScope(UnconfinedTestDispatcher()),
    )

    private fun clear(vm: TransferViewModel) {
        val store = ViewModelStore()
        store.put("transfer", vm)
        store.clear()
    }

    @Test
    fun `a started receive session releases exactly one lease on teardown`() = runTest {
        coEvery { startTransferServer.invoke(Unit) } returns Unit

        val vm = newVm()
        vm.onReceiveClick()
        clear(vm)

        coVerify(exactly = 1) { startTransferServer.invoke(Unit) }
        coVerify(exactly = 1) { stopTransferServer.invoke(Unit) }
    }

    @Test
    fun `a failed start releases no lease on teardown`() = runTest {
        coEvery { startTransferServer.invoke(Unit) } throws IllegalStateException("bind refused")

        val vm = newVm()
        vm.onReceiveClick()
        clear(vm)

        coVerify(exactly = 1) { startTransferServer.invoke(Unit) }
        coVerify(exactly = 0) {
            stopTransferServer.invoke(Unit)
        }
        assertEquals("bind refused", vm.transferError.value)
        assertNull(vm.isReceiving.value)
    }

    /**
     * Review finding 3: two taps before `isReceiving` ever recomposes the button away must still
     * take out only one lease. The second click has to be dropped while the first is still mid
     * `startTransferServer()`, not merely once `holdingLease` is set - a flag set from inside the
     * first tap's own coroutine would only close the window after the fact, not while it is open.
     */
    @Test
    fun `a double tap of receive takes out only one lease`() = runTest {
        val gate = CompletableDeferred<Unit>()
        coEvery { startTransferServer.invoke(Unit) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onReceiveClick()
        vm.onReceiveClick() // dropped: the first tap's job is still active, parked mid-bind

        coVerify(exactly = 1) { startTransferServer.invoke(Unit) }

        gate.complete(Unit)
        clear(vm)

        coVerify(exactly = 1) { stopTransferServer.invoke(Unit) }
    }
}
