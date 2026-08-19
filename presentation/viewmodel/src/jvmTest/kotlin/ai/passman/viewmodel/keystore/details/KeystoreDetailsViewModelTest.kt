package ai.passman.viewmodel.keystore.details

import ai.passman.domain.keystore.DeleteKeystore
import ai.passman.domain.keystore.DeleteKeystoreKey
import ai.passman.domain.keystore.GetKeystore
import ai.passman.domain.keystore.GetKeystoreAliases
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.ShareFileKind
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/** Pins that the keystore file never leaves the app without a confirmed, correctly-named request. */
@OptIn(ExperimentalCoroutinesApi::class)
class KeystoreDetailsViewModelTest {
    private val getKeystore: GetKeystore = mockk(relaxed = true)
    private val getKeystoreAliases: GetKeystoreAliases = mockk(relaxed = true)
    private val deleteKeystore: DeleteKeystore = mockk(relaxed = true)
    private val deleteKeystoreKey: DeleteKeystoreKey = mockk(relaxed = true)
    private val shareFile: ShareFile = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = KeystoreDetailsViewModel(
        keystorePath = "/stores",
        keystoreName = "default.pfx",
        getKeystore = getKeystore,
        getKeystoreAliases = getKeystoreAliases,
        deleteKeystore = deleteKeystore,
        deleteKeystoreKey = deleteKeystoreKey,
        shareFile = shareFile,
    )

    @Test
    fun `share click stages the keystore file and only a confirmation releases it`() = runTest {
        val vm = newVm()

        vm.onShareKeystoreClick()

        val staged = assertNotNull(vm.pendingShare.value)
        assertEquals("/stores/default.pfx", staged.filePath)
        assertEquals("default.pfx", staged.displayName)
        assertEquals(ShareFileKind.EntireKeystore, staged.kind)
        coVerify(exactly = 0) { shareFile.invoke(any()) }

        vm.onShareConfirmed()

        coVerify(exactly = 1) { shareFile.invoke(staged) }
        assertNull(vm.pendingShare.value)
    }

    @Test
    fun `dismissing the confirmation shares nothing`() = runTest {
        val vm = newVm()
        vm.onShareKeystoreClick()

        vm.onShareDismissed()

        assertNull(vm.pendingShare.value)
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }
}
