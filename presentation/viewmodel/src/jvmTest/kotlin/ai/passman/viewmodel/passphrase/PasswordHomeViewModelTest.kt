package ai.passman.viewmodel.passphrase

import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.password.DeletePasswords
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.settings.SyncPasswords
import ai.passman.viewmodel.sync.SyncTargetPickerState
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

@OptIn(ExperimentalCoroutinesApi::class)
class PasswordHomeViewModelTest {
    private val getPasswordEntries: GetPasswordEntries = mockk(relaxed = true)
    private val syncPasswords: SyncPasswords = mockk(relaxed = true)
    private val getSyncTargets: GetSyncTargets = mockk(relaxed = true)
    private val updateTrustedDeviceHost: UpdateTrustedDeviceHost = mockk(relaxed = true)
    private val deletePasswords: DeletePasswords = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getPasswordEntries.invoke(Unit) } returns emptyFlow()
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = PasswordHomeViewModel(
        getPasswordEntries = getPasswordEntries,
        syncPasswords = syncPasswords,
        getSyncTargets = getSyncTargets,
        updateTrustedDeviceHost = updateTrustedDeviceHost,
        deletePasswords = deletePasswords,
    )

    private fun device(name: String, host: String = "10.0.0.1") = TrustedDevice(
        name = name, fingerprint = "fp-$name", lastHost = host,
    )

    @Test
    fun `sync with no trusted devices prompts to pair instead of starting`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns emptyList()
        val vm = newVm()
        vm.onSyncClick()
        assertEquals(SyncTargetPickerState.NoDevices, vm.syncTargetPicker.state.value)
        verify(exactly = 0) { syncPasswords.invoke(any()) }
    }

    @Test
    fun `sync with one trusted device starts immediately against its lastHost`() = runTest {
        coEvery { getSyncTargets.invoke(Unit) } returns listOf(device("desk", host = "10.0.0.7"))
        every { syncPasswords.invoke("10.0.0.7") } returns emptyFlow()
        val vm = newVm()
        vm.onSyncClick()
        verify(exactly = 1) { syncPasswords.invoke("10.0.0.7") }
    }

    @Test
    fun `sync with two trusted devices opens the chooser`() = runTest {
        val targets = listOf(device("desk"), device("phone"))
        coEvery { getSyncTargets.invoke(Unit) } returns targets
        val vm = newVm()
        vm.onSyncClick()
        assertEquals(SyncTargetPickerState.Choosing(targets), vm.syncTargetPicker.state.value)
        verify(exactly = 0) { syncPasswords.invoke(any()) }
    }

    @Test
    fun `choosing a device from the chooser starts the session and hides it`() = runTest {
        every { syncPasswords.invoke("10.0.0.8") } returns emptyFlow()
        val vm = newVm()
        vm.onSyncTargetChosen(device("phone", host = "10.0.0.8"))
        assertEquals(SyncTargetPickerState.Hidden, vm.syncTargetPicker.state.value)
        verify(exactly = 1) { syncPasswords.invoke("10.0.0.8") }
    }

    @Test
    fun `deleteSelected forwards the full selection set in a single batch call`() = runTest {
        coEvery { deletePasswords.invoke(any()) } returns 3

        val vm = newVm()
        vm.toggleSelect("1")
        vm.toggleSelect("3")
        vm.toggleSelect("5")
        assertEquals(setOf("1", "3", "5"), vm.selectedIds.value)

        vm.deleteSelected()

        coVerify(exactly = 1) { deletePasswords.invoke(setOf("1", "3", "5")) }
        assertTrue(vm.selectedIds.value.isEmpty())
    }

    @Test
    fun `deleteSelected reports full-success snackbar`() = runTest {
        coEvery { deletePasswords.invoke(any()) } returns 3

        val vm = newVm()
        vm.toggleSelect("1"); vm.toggleSelect("2"); vm.toggleSelect("3")

        vm.deleteSelected()

        assertEquals("Deleted 3 passwords", vm.userMessages.receive())
    }

    @Test
    fun `deleteSelected reports partial-success snackbar`() = runTest {
        coEvery { deletePasswords.invoke(any()) } returns 2

        val vm = newVm()
        vm.toggleSelect("1"); vm.toggleSelect("2"); vm.toggleSelect("3")

        vm.deleteSelected()

        assertEquals("Deleted 2 of 3 passwords; 1 failed", vm.userMessages.receive())
    }

    /**
     * The toast has to agree with the confirmation dialog, which counts `selectedIds.size`.
     *
     * This is not hypothetical arithmetic. Before `deletePasswordEntries` was hardened to remove one
     * row per uuid, a vault holding two entries that shared a derived identity answered a selection
     * of one with `removed = 2` — the dialog asked "Delete password?" and the toast then said two had
     * gone. The repository no longer does that; the clamp is what keeps the two numbers consistent
     * even if some future path starts over-reporting again.
     */
    @Test
    fun `deleteSelected never reports more deletions than the user selected`() = runTest {
        coEvery { deletePasswords.invoke(any()) } returns 2

        val vm = newVm()
        vm.toggleSelect("1")

        vm.deleteSelected()

        assertEquals("Deleted 1 password", vm.userMessages.receive())
    }

    @Test
    fun `deleteSelected with empty selection is a no-op`() = runTest {
        val vm = newVm()
        vm.deleteSelected()
        coVerify(exactly = 0) { deletePasswords.invoke(any()) }
    }

    @Test
    fun `search matches name username website and notes`() = runTest {
        coEvery { getPasswordEntries.invoke(Unit) } returns flowOf(
            listOf(
                entry(uuid = "1", name = "Gmail", username = "mia@gmail.com", website = "https://mail.google.com", notes = "personal"),
                entry(uuid = "2", name = "Bank", username = "sterling", website = "https://mybank.example", notes = "joint account"),
            ),
        )
        val vm = newVm()

        vm.onSearchQueryChanged("mybank.example")
        assertEquals(listOf("Bank"), vm.entryList.value.map { it.entryName })

        vm.onSearchQueryChanged("mia@")
        assertEquals(listOf("Gmail"), vm.entryList.value.map { it.entryName })

        vm.onSearchQueryChanged("joint")
        assertEquals(listOf("Bank"), vm.entryList.value.map { it.entryName })

        vm.onSearchQueryChanged("Gmail")
        assertEquals(listOf("Gmail"), vm.entryList.value.map { it.entryName })

        vm.onSearchQueryChanged("")
        assertEquals(listOf("Gmail", "Bank"), vm.entryList.value.map { it.entryName })
    }

    @Test
    fun `search does not match on the stored password itself`() = runTest {
        coEvery { getPasswordEntries.invoke(Unit) } returns flowOf(
            listOf(
                entry(uuid = "1", name = "Gmail", username = "mia@gmail.com", website = "https://mail.google.com", notes = "personal"),
            ),
        )
        val vm = newVm()

        vm.onSearchQueryChanged("hunter2")
        assertEquals(emptyList(), vm.entryList.value)
    }

    private fun entry(uuid: String, name: String, username: String, website: String, notes: String) =
        PasswordEntry(
            id = uuid,
            entryName = name,
            username = username,
            password = "hunter2",
            website = website,
            notes = notes,
            dateCreated = 0L,
            uuid = uuid,
        )

    @Test
    fun `toggleSelect adds and removes ids`() = runTest {
        val vm = newVm()
        vm.toggleSelect("a")
        vm.toggleSelect("b")
        assertEquals(setOf("a", "b"), vm.selectedIds.value)
        vm.toggleSelect("a")
        assertEquals(setOf("b"), vm.selectedIds.value)
    }
}
