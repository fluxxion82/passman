package ai.passman.viewmodel.sync

import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest

class SyncTargetPickerTest {
    private val getSyncTargets: GetSyncTargets = mockk(relaxed = true)
    private val updateTrustedDeviceHost: UpdateTrustedDeviceHost = mockk(relaxed = true)
    private val picker = SyncTargetPicker(getSyncTargets, updateTrustedDeviceHost)

    private fun device(name: String, host: String = "10.0.0.$name".take(12)) = TrustedDevice(
        name = name, fingerprint = "fp-$name", lastHost = host,
    )

    @Test
    fun `requestSync with no devices shows the pairing prompt`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns emptyList()
        var synced: TrustedDevice? = null
        picker.requestSync { synced = it }
        assertEquals(SyncTargetPickerState.NoDevices, picker.state.value)
        assertNull(synced)
    }

    @Test
    fun `requestSync with one device syncs immediately without a chooser`() = runTest {
        val only = device("desk")
        coEvery { getSyncTargets.invoke(Unit) } returns listOf(only)
        var synced: TrustedDevice? = null
        picker.requestSync { synced = it }
        assertEquals(SyncTargetPickerState.Hidden, picker.state.value)
        assertEquals(only, synced)
    }

    @Test
    fun `requestSync with two devices opens the chooser and does not sync`() = runTest {
        val targets = listOf(device("desk"), device("phone"))
        coEvery { getSyncTargets.invoke(Unit) } returns targets
        var synced: TrustedDevice? = null
        picker.requestSync { synced = it }
        assertEquals(SyncTargetPickerState.Choosing(targets), picker.state.value)
        assertNull(synced)
    }

    @Test
    fun `open always shows the chooser, even for a single device`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns listOf(device("desk"))
        picker.open()
        assertEquals(
            SyncTargetPickerState.Choosing(listOf(device("desk"))),
            picker.state.value,
        )
    }

    @Test
    fun `open with no devices shows the pairing prompt`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns emptyList()
        picker.open()
        assertEquals(SyncTargetPickerState.NoDevices, picker.state.value)
    }

    @Test
    fun `editHost persists and refreshes an open chooser`() = runTest {
        val before = listOf(device("desk"))
        val after = listOf(device("desk", host = "10.0.0.99"))
        coEvery { getSyncTargets.invoke(Unit) } returnsMany listOf(before, after)
        picker.open()
        picker.editHost("desk", "10.0.0.99")
        coVerify {
            updateTrustedDeviceHost.invoke(
                UpdateTrustedDeviceHost.Parameters(name = "desk", host = "10.0.0.99"),
            )
        }
        assertEquals(SyncTargetPickerState.Choosing(after), picker.state.value)
    }

    @Test
    fun `dismiss landing during editHost's refresh does not resurrect the chooser`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns listOf(device("desk"))
        picker.open()
        // The user hits Cancel while editHost's refreshed list is still being fetched.
        coEvery { getSyncTargets.invoke(Unit) } coAnswers {
            picker.dismiss()
            listOf(device("desk", host = "10.0.0.99"))
        }
        picker.editHost("desk", "10.0.0.99")
        coVerify {
            updateTrustedDeviceHost.invoke(
                UpdateTrustedDeviceHost.Parameters(name = "desk", host = "10.0.0.99"),
            )
        }
        assertEquals(SyncTargetPickerState.Hidden, picker.state.value)
    }

    @Test
    fun `overlapping requestSync calls start only one session`() = runTest {
        val only = device("desk")
        val firstFetch = CompletableDeferred<Unit>()
        var fetches = 0
        coEvery { getSyncTargets.invoke(Unit) } coAnswers {
            if (++fetches == 1) firstFetch.await()
            listOf(only)
        }
        var sessions = 0
        val first = launch { picker.requestSync { sessions++ } }
        runCurrent() // first call is now parked inside getSyncTargets
        picker.requestSync { sessions++ } // second click lands while the first is in flight
        firstFetch.complete(Unit)
        first.join()
        assertEquals(1, sessions)

        // The guard resets: a later click syncs again.
        picker.requestSync { sessions++ }
        assertEquals(2, sessions)
    }

    @Test
    fun `dismiss hides whatever is showing`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns emptyList()
        picker.open()
        picker.dismiss()
        assertEquals(SyncTargetPickerState.Hidden, picker.state.value)
    }
}
