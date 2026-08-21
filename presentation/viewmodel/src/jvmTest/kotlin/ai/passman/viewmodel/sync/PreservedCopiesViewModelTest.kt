package ai.passman.viewmodel.sync

import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.settings.DeletePreservedCopy
import ai.passman.domain.settings.GetPreservedCopies
import ai.passman.domain.settings.GetPreservedCopyPath
import ai.passman.domain.settings.RestorePreservedCopy
import ai.passman.domain.settings.ShareFile
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.model.ShareFileKind
import ai.passman.domain.user.VerifyMasterPassword
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * Pins the contract of the screen that reaches displaced key material: nothing happens on a tap,
 * every action is re-read from the repository afterwards, and two confirmations can never be up at
 * once — a user answering one dialog must not be answering a different action than they think.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PreservedCopiesViewModelTest {
    private val getPreservedCopies: GetPreservedCopies = mockk(relaxed = true)
    private val restorePreservedCopy: RestorePreservedCopy = mockk(relaxed = true)
    private val deletePreservedCopy: DeletePreservedCopy = mockk(relaxed = true)
    private val getPreservedCopyPath: GetPreservedCopyPath = mockk(relaxed = true)
    private val shareFile: ShareFile = mockk(relaxed = true)
    private val verifyMasterPassword: VerifyMasterPassword = mockk(relaxed = true)

    private val copy = PreservedCopy(
        artifact = SyncOps.PGP,
        id = "${"a".repeat(32)}-work_secret_ring.asc",
        originalName = "work_secret_ring.asc",
        sizeBytes = 2_048,
        modifiedAt = 1_700_000_000_000,
    )

    @BeforeTest
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getPreservedCopies.invoke(Unit) } returns listOf(copy)
    }

    @AfterTest
    fun tearDown() = Dispatchers.resetMain()

    private fun newVm() = PreservedCopiesViewModel(
        getPreservedCopies = getPreservedCopies,
        restorePreservedCopy = restorePreservedCopy,
        deletePreservedCopy = deletePreservedCopy,
        getPreservedCopyPath = getPreservedCopyPath,
        shareFile = shareFile,
        verifyMasterPassword = verifyMasterPassword,
    )

    @Test
    fun `lists on open`() = runTest {
        assertEquals(listOf(copy), newVm().copies.value)
    }

    @Test
    fun `a tap stages and changes nothing`() = runTest {
        val viewModel = newVm()

        viewModel.onRestoreClicked(copy)
        viewModel.onDeleteClicked(copy)

        coVerify(exactly = 0) { restorePreservedCopy.invoke(any()) }
        coVerify(exactly = 0) { deletePreservedCopy.invoke(any()) }
    }

    @Test
    fun `restoring reloads, because restore swaps rather than removes`() = runTest {
        coEvery { restorePreservedCopy.invoke(copy) } returns true
        val viewModel = newVm()

        viewModel.onRestoreClicked(copy)
        viewModel.onRestoreConfirmed()

        // Twice: once on open, once after. The restored copy leaves the store and the version it
        // displaced enters it, so the list cannot be patched in place from what the caller knows.
        coVerify(exactly = 2) { getPreservedCopies.invoke(Unit) }
        assertNull(viewModel.pendingRestore.value)
    }

    @Test
    fun `a failed delete says so instead of reporting success`() = runTest {
        coEvery { deletePreservedCopy.invoke(copy) } returns false
        val viewModel = newVm()

        viewModel.onDeleteClicked(copy)
        viewModel.onDeleteConfirmed()

        assertTrue(viewModel.userMessages.tryReceive().getOrNull()?.contains("Couldn't delete") == true)
    }

    @Test
    fun `confirming twice acts once`() = runTest {
        coEvery { deletePreservedCopy.invoke(copy) } returns true
        val viewModel = newVm()

        viewModel.onDeleteClicked(copy)
        viewModel.onDeleteConfirmed()
        viewModel.onDeleteConfirmed()

        coVerify(exactly = 1) { deletePreservedCopy.invoke(copy) }
    }

    @Test
    fun `export asks for the master password before resolving anything`() = runTest {
        val viewModel = newVm()

        viewModel.onExportClicked(copy)

        assertEquals(copy, viewModel.pendingExportPassword.value)
        assertNull(viewModel.pendingShare.value, "nothing is staged until the password is verified")
        // Not even the path: a wrong password must not learn whether the file is still there.
        coVerify(exactly = 0) { getPreservedCopyPath.invoke(any()) }
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }

    @Test
    fun `a wrong master password exports nothing and keeps the prompt up`() = runTest {
        coEvery { verifyMasterPassword.invoke(any()) } returns false
        val viewModel = newVm()

        viewModel.onExportClicked(copy)
        viewModel.onExportPasswordEntered("not-it")

        assertNotNull(viewModel.exportPasswordError.value)
        assertEquals(copy, viewModel.pendingExportPassword.value, "the prompt stays up to retry")
        assertNull(viewModel.pendingShare.value)
        coVerify(exactly = 0) { getPreservedCopyPath.invoke(any()) }
    }

    @Test
    fun `the right master password stages the kind that claims the least`() = runTest {
        coEvery { verifyMasterPassword.invoke("correct-horse") } returns true
        coEvery { getPreservedCopyPath.invoke(copy) } returns "/tmp/store/${copy.id}"
        val viewModel = newVm()

        viewModel.onExportClicked(copy)
        viewModel.onExportPasswordEntered("correct-horse")

        val staged = assertNotNull(viewModel.pendingShare.value)
        // Not PrivateKey: that wording promises the file is passphrase-protected, and a displaced
        // copy may be a public ring or a whole keystore. Nothing in the store distinguishes them.
        assertEquals(ShareFileKind.DisplacedVersion, staged.kind)
        assertEquals(copy.originalName, staged.displayName)
        assertNull(viewModel.pendingExportPassword.value)
        // Still nothing shared: the password gate is in front of the confirmation, not instead of it.
        coVerify(exactly = 0) { shareFile.invoke(any()) }
    }

    @Test
    fun `export will not raise a prompt over a dialog already open`() = runTest {
        val viewModel = newVm()

        viewModel.onDeleteClicked(copy)
        viewModel.onExportClicked(copy)

        // Otherwise the prompt lands on top of the delete confirmation the user is reading, and the
        // button they press answers a question they were never asked.
        assertNull(viewModel.pendingExportPassword.value)
        assertEquals(copy, viewModel.pendingDelete.value)
    }
}
