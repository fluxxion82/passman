package ai.passman.viewmodel.keystore

import ai.passman.domain.connectivity.GetSyncTargets
import ai.passman.domain.connectivity.UpdateTrustedDeviceHost
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.keystore.DeleteKeystore
import ai.passman.domain.keystore.GetAllKeystores
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.settings.SyncKeystores
import ai.passman.domain.user.GetAppUser
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.viewmodel.sync.SyncTargetPickerState
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
class KeystoreHomeViewModelTest {
    private val getAllKeystores: GetAllKeystores = mockk(relaxed = true)
    private val syncKeystores: SyncKeystores = mockk(relaxed = true)
    private val getSyncTargets: GetSyncTargets = mockk(relaxed = true)
    private val updateTrustedDeviceHost: UpdateTrustedDeviceHost = mockk(relaxed = true)
    private val deleteKeystore: DeleteKeystore = mockk(relaxed = true)
    private val getAppUser: GetAppUser = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getAllKeystores.invoke(Unit) } returns emptyFlow()
        coEvery { getAppUser.invoke(Unit) } returns emptyFlow()
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = KeystoreHomeViewModel(
        getAllKeystores = getAllKeystores,
        syncKeystores = syncKeystores,
        getSyncTargets = getSyncTargets,
        updateTrustedDeviceHost = updateTrustedDeviceHost,
        deleteKeystore = deleteKeystore,
        getAppUser = getAppUser,
    )

    private fun device(name: String, host: String = "10.0.0.1") = TrustedDevice(
        name = name, fingerprint = "fp-$name", lastHost = host,
    )

    @Test
    fun `sync with two trusted devices opens the chooser instead of starting`() = runTest {
        val targets = listOf(device("desk"), device("phone"))
        coEvery { getSyncTargets.invoke(Unit) } returns targets

        val vm = newVm()
        vm.onSyncClick()

        assertEquals(SyncTargetPickerState.Choosing(targets), vm.syncTargetPicker.state.value)
        verify(exactly = 0) { syncKeystores.invoke(any()) }
    }

    private fun keystore(name: String) = KeyStoreInfo(
        path = "/keys/ster",
        name = name,
        keystorePassword = "",
        keyList = emptyList(),
        type = KeyStoreType.PKCS12,
    )

    @Test
    fun `currentUserName populates from LoggedIn AppUser`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()

        assertEquals("ster", vm.currentUserName.value)
    }

    @Test
    fun `currentUserName populates from AccountCreated AppUser`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.AccountCreated(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()

        assertEquals("ster", vm.currentUserName.value)
    }

    @Test
    fun `currentUserName is null for Anonymous AppUser`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(AppUser.Anonymous)

        val vm = newVm()

        assertEquals(null, vm.currentUserName.value)
    }

    @Test
    fun `isProtected matches login keystore filename ignoring case`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()

        assertTrue(vm.isProtected(keystore("ster.pfx")))
        assertTrue(vm.isProtected(keystore("STER.PFX")))
    }

    @Test
    fun `isProtected is false for non-login keystores`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()

        assertFalse(vm.isProtected(keystore("work.pfx")))
        assertFalse(vm.isProtected(keystore("personal.jks")))
        assertFalse(vm.isProtected(keystore("ster")))           // no extension
        assertFalse(vm.isProtected(keystore("aster.pfx")))      // substring, not equal
    }

    @Test
    fun `isProtected is false before user emits`() = runTest {
        // getAppUser returns empty flow, so currentUserName stays null
        val vm = newVm()

        assertFalse(vm.isProtected(keystore("ster.pfx")))
    }

    @Test
    fun `toggleSelect ignores protected keystore`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()
        vm.toggleSelect(keystore("ster.pfx"))

        assertTrue(vm.selectedIds.value.isEmpty())
    }

    @Test
    fun `toggleSelect adds non-protected keystore`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()
        val target = keystore("work.pfx")
        vm.toggleSelect(target)

        assertTrue(vm.keystoreId(target) in vm.selectedIds.value)
    }

    @Test
    fun `onKeystoreLongPress on protected emits user message`() = runTest {
        coEvery { getAppUser.invoke(Unit) } returns flowOf(
            AppUser.LoggedIn(userName = "ster", password = Password(hash = "h", salt = "s"))
        )

        val vm = newVm()
        vm.onKeystoreLongPress(keystore("ster.pfx"))

        val message = vm.userMessages.receive()
        assertEquals("This keystore is required for login and can't be deleted", message)
        assertTrue(vm.selectedIds.value.isEmpty())
    }
}
