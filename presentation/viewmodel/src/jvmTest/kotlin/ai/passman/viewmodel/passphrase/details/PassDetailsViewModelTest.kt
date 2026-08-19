package ai.passman.viewmodel.passphrase.details

import ai.passman.domain.password.DecodeTotpQrImage
import ai.passman.domain.password.DeletePassword
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.GetPassword
import ai.passman.domain.password.UpdatePassword
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.model.EntryActivity
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.viewvo.passphrase.Back
import ai.passman.viewvo.passphrase.Copied
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * Navigating `Back` is this screen's *success* signal: the detail screen closes when — and only
 * when — the edit or the delete actually reached the vault. A repository save can lose its
 * conditional publish and exhaust its retries, and until the use cases surfaced that, this screen
 * closed anyway and the user walked off believing a credential was saved that never was.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PassDetailsViewModelTest {
    private val getPassword: GetPassword = mockk(relaxed = true)
    private val updatePassword: UpdatePassword = mockk(relaxed = true)
    private val deletePassword: DeletePassword = mockk(relaxed = true)
    private val copyToClipboard: CopyToClipboard = mockk(relaxed = true)

    private val stored = PasswordEntry(
        uuid = "uuid-harbour",
        id = "2",
        entryName = "harbour",
        username = "dana",
        password = "pw-harbour",
        website = "https://harbour.example",
        notes = "",
        dateCreated = 41L,
    )

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getPassword.invoke("uuid-harbour") } returns stored
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private var epochSeconds = 59L
    private val decodeTotpQrImage: DecodeTotpQrImage = mockk(relaxed = true)

    private fun newVm() = PassDetailsViewModel(
        passwordUuid = "uuid-harbour",
        getPassword = getPassword,
        updatePassword = updatePassword,
        deletePassword = deletePassword,
        copyToClipboard = copyToClipboard,
        generateTotpCode = GenerateTotpCode(epochSeconds = { epochSeconds }),
        decodeTotpQrImage = decodeTotpQrImage,
    )

    @Test
    fun `a successful save navigates back`() = runTest {
        coEvery { updatePassword.invoke(any()) } returns true

        val vm = newVm()
        vm.onSaveClick()

        assertEquals(Back, vm.navigation.tryReceive().getOrNull())
    }

    @Test
    fun `a failed save stays on the screen`() = runTest {
        coEvery { updatePassword.invoke(any()) } returns false

        val vm = newVm()
        vm.onSaveClick()

        assertNull(vm.navigation.tryReceive().getOrNull(), "closing the screen would report a save that never landed")
    }

    @Test
    fun `a successful delete navigates back`() = runTest {
        coEvery { deletePassword.invoke("uuid-harbour") } returns true

        val vm = newVm()
        vm.onDeleteClicked()

        assertEquals(Back, vm.navigation.tryReceive().getOrNull())
    }

    @Test
    fun `a failed delete stays on the screen`() = runTest {
        coEvery { deletePassword.invoke("uuid-harbour") } returns false

        val vm = newVm()
        vm.onDeleteClicked()

        assertNull(vm.navigation.tryReceive().getOrNull(), "closing the screen would report a delete that never landed")
    }

    // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ is base32 for the RFC 6238 test secret; at t=59 the 6-digit code is 287082.
    private val rfcSeed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    /** The ticker only runs while collected, so every totp test watches the flow the way a screen would. */
    private fun kotlinx.coroutines.test.TestScope.watchTotp(vm: PassDetailsViewModel) {
        backgroundScope.launch { vm.totpCode.collect {} }
    }

    @Test
    fun `a stored totp seed produces the rolling code`() = runTest {
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(totpSeed = rfcSeed)

        val vm = newVm()
        watchTotp(vm)
        runCurrent()

        assertEquals("287082", vm.totpCode.value?.code)
        assertEquals(1, vm.totpCode.value?.secondsRemaining)
    }

    @Test
    fun `the code rolls over when the period ends`() = runTest {
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(totpSeed = rfcSeed)

        val vm = newVm()
        watchTotp(vm)
        runCurrent()
        epochSeconds = 60L
        advanceTimeBy(1_001)
        runCurrent()

        assertEquals("359152", vm.totpCode.value?.code)
    }

    @Test
    fun `an entry without a seed shows no code`() = runTest {
        val vm = newVm()
        watchTotp(vm)
        runCurrent()
        assertNull(vm.totpCode.value)
    }

    @Test
    fun `copying the totp code goes through the clipboard use case`() = runTest {
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(totpSeed = rfcSeed)

        val vm = newVm()
        watchTotp(vm)
        runCurrent()
        vm.onTotpCopyClicked()

        assertEquals(Copied, vm.navigation.tryReceive().getOrNull())
        coVerify { copyToClipboard.invoke("287082") }
    }

    @Test
    fun `custom fields load from the entry and survive a save`() = runTest {
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(
            customFields = listOf(CustomField(label = "pin", value = "1234", secret = true)),
        )
        coEvery { updatePassword.invoke(any()) } returns true

        val vm = newVm()
        runCurrent()
        assertEquals(listOf("pin"), vm.customFields.value.map { it.label })

        vm.onCustomFieldValueChanged(0, "5678")
        vm.onSaveClick()

        val saved = slot<PasswordEntry>()
        coVerify { updatePassword.invoke(capture(saved)) }
        assertEquals(listOf(CustomField(label = "pin", value = "5678", secret = true)), saved.captured.customFields)
        assertEquals("uuid-harbour", saved.captured.uuid, "identity must ride along untouched")
    }

    @Test
    fun `the history flows publish the fetched entry's values`() = runTest {
        val records = listOf(EntryActivity(at = 10L, kind = EntryActivity.KIND_CREATED))
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(
            createdAt = 10L,
            dateCreated = 30L,
            activity = records,
        )

        val vm = newVm()
        runCurrent()

        assertEquals(10L, vm.createdAt.value)
        assertEquals(30L, vm.lastEditedAt.value)
        assertEquals(records, vm.activity.value)
    }

    @Test
    fun `an entry with no activity still publishes both timestamps`() = runTest {
        // A legacy row: createdAt backfilled equal to dateCreated, activity never populated.
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(
            createdAt = 41L,
            dateCreated = 41L,
            activity = emptyList(),
        )

        val vm = newVm()
        runCurrent()

        assertEquals(41L, vm.createdAt.value)
        assertEquals(41L, vm.lastEditedAt.value)
        assertEquals(emptyList(), vm.activity.value)
    }


    @Test
    fun `an edited totp seed is validated and saved`() = runTest {
        coEvery { updatePassword.invoke(any()) } returns true

        val vm = newVm()
        runCurrent()
        vm.onTotpSeedChanged(rfcSeed)
        vm.onSaveClick()

        val saved = slot<PasswordEntry>()
        coVerify { updatePassword.invoke(capture(saved)) }
        assertEquals(rfcSeed, saved.captured.totpSeed)
    }

    @Test
    fun `a picked qr image fills the totp seed`() = runTest {
        coEvery { decodeTotpQrImage.invoke("/cache/qr.png") } returns
            DecodeTotpQrImage.Result.Seed(rfcSeed)

        val vm = newVm()
        vm.onQrImagePicked("/cache/qr.png")

        assertEquals(rfcSeed, vm.totpSeed.value)
    }

    @Test
    fun `a failed qr decode reports the reason without touching the seed`() = runTest {
        coEvery { getPassword.invoke("uuid-harbour") } returns stored.copy(totpSeed = rfcSeed)
        coEvery { decodeTotpQrImage.invoke(any()) } returns DecodeTotpQrImage.Result.NoQrFound

        val vm = newVm()
        vm.onQrImagePicked("/cache/photo.png")

        assertEquals(
            ai.passman.viewvo.passphrase.ShowMessage("No QR code found in that image"),
            vm.navigation.tryReceive().getOrNull(),
        )
        assertEquals(rfcSeed, vm.totpSeed.value)
    }

    @Test
    fun `an unreadable image file reports the reason`() = runTest {
        coEvery { decodeTotpQrImage.invoke(any()) } returns DecodeTotpQrImage.Result.UnreadableImage

        val vm = newVm()
        vm.onQrImagePicked("/cache/photo.heic")

        assertEquals(
            ai.passman.viewvo.passphrase.ShowMessage("Couldn't read that image file — try a PNG or JPEG"),
            vm.navigation.tryReceive().getOrNull(),
        )
    }

    @Test
    fun `a camera scan of a default uri fills the field with the bare secret`() = runTest {
        val vm = newVm()
        vm.onQrScanned("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")

        assertEquals("JBSWY3DPEHPK3PXP", vm.totpSeed.value)
    }

    @Test
    fun `a second save click while one is in flight is ignored`() = runTest {
        coEvery { updatePassword.invoke(any()) } coAnswers {
            kotlinx.coroutines.delay(5_000)
            true
        }

        val vm = newVm()
        vm.onSaveClick()
        vm.onSaveClick()
        advanceTimeBy(6_000)

        assertEquals(Back, vm.navigation.tryReceive().getOrNull())
        coVerify(exactly = 1) { updatePassword.invoke(any()) }
    }

    @Test
    fun `a failed save frees the button for a retry`() = runTest {
        coEvery { updatePassword.invoke(any()) } returns false

        val vm = newVm()
        vm.onSaveClick()
        vm.onSaveClick()

        coVerify(exactly = 2) { updatePassword.invoke(any()) }
    }

    @Test
    fun `an unparseable totp seed blocks the save`() = runTest {
        val vm = newVm()
        runCurrent()
        vm.onTotpSeedChanged("not base32 !!")
        vm.onSaveClick()

        coVerify(exactly = 0) { updatePassword.invoke(any()) }
        assertNull(vm.navigation.tryReceive().getOrNull()?.takeIf { it == Back }, "the screen must not close")
    }
}
