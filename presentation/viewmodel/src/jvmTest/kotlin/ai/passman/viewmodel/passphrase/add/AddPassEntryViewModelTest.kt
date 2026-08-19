package ai.passman.viewmodel.passphrase.add

import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.DecodeTotpQrImage
import ai.passman.domain.password.GenerateTotpCode
import ai.passman.domain.password.model.CustomField
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.viewvo.navigation.InvalidEntry
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

@OptIn(ExperimentalCoroutinesApi::class)
class AddPassEntryViewModelTest {
    private val addPassword: AddPassword = mockk(relaxed = true)
    private val passwordEventPersistence: PasswordEventPersistence = mockk(relaxed = true)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(StandardTestDispatcher())
        coEvery { passwordEventPersistence.events() } returns emptyFlow()
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private val decodeTotpQrImage: DecodeTotpQrImage = mockk(relaxed = true)

    private fun newVm() = AddPassEntryViewModel(
        addPassword = addPassword,
        passwordEventPersistence = passwordEventPersistence,
        generateTotpCode = GenerateTotpCode(epochSeconds = { 59L }),
        decodeTotpQrImage = decodeTotpQrImage,
    )

    @Test
    fun `save forwards the totp seed and custom fields`() = runTest {
        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onTotpSeedChanged("JBSWY3DPEHPK3PXP")
        vm.onAddCustomField()
        vm.onCustomFieldLabelChanged(0, "pin")
        vm.onCustomFieldValueChanged(0, "1234")
        vm.onCustomFieldSecretToggled(0)
        runCurrent()

        vm.onSaveClick()
        runCurrent()

        val saved = slot<AddPassword.EntryData>()
        coVerify(exactly = 1) { addPassword.invoke(capture(saved)) }
        assertEquals("JBSWY3DPEHPK3PXP", saved.captured.totpSeed)
        assertEquals(listOf(CustomField(label = "pin", value = "1234", secret = true)), saved.captured.customFields)
    }

    @Test
    fun `empty custom field rows are dropped on save`() = runTest {
        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onAddCustomField()
        vm.onAddCustomField()
        vm.onCustomFieldLabelChanged(1, "seat")
        vm.onCustomFieldValueChanged(1, "12F")
        runCurrent()

        vm.onSaveClick()
        runCurrent()

        val saved = slot<AddPassword.EntryData>()
        coVerify(exactly = 1) { addPassword.invoke(capture(saved)) }
        assertEquals(listOf(CustomField(label = "seat", value = "12F")), saved.captured.customFields)
    }

    @Test
    fun `an unparseable totp seed blocks the save`() = runTest {
        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onTotpSeedChanged("not base32 !!")
        runCurrent()

        vm.onSaveClick()
        runCurrent()

        assertIs<InvalidEntry>(vm.navigation.receive())
        coVerify(exactly = 0) { addPassword.invoke(any()) }
    }

    @Test
    fun `an otpauth uri seed is accepted`() = runTest {
        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onTotpSeedChanged("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=8")
        runCurrent()

        vm.onSaveClick()
        runCurrent()

        coVerify(exactly = 1) { addPassword.invoke(any()) }
    }

    @Test
    fun `a picked qr image fills the totp seed`() = runTest {
        coEvery { decodeTotpQrImage.invoke("/cache/qr.png") } returns
            DecodeTotpQrImage.Result.Seed("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")

        val vm = newVm()
        vm.onQrImagePicked("/cache/qr.png")
        runCurrent()

        assertEquals("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP", vm.totpSeed.value)
    }

    @Test
    fun `an image without a qr reports the reason and keeps the seed`() = runTest {
        coEvery { decodeTotpQrImage.invoke(any()) } returns DecodeTotpQrImage.Result.NoQrFound

        val vm = newVm()
        vm.onTotpSeedChanged("JBSWY3DPEHPK3PXP")
        runCurrent()
        vm.onQrImagePicked("/cache/photo.png")
        runCurrent()

        assertEquals(InvalidEntry("No QR code found in that image"), vm.navigation.receive())
        assertEquals("JBSWY3DPEHPK3PXP", vm.totpSeed.value)
    }

    @Test
    fun `an unreadable image file reports the reason`() = runTest {
        coEvery { decodeTotpQrImage.invoke(any()) } returns DecodeTotpQrImage.Result.UnreadableImage

        val vm = newVm()
        vm.onQrImagePicked("/cache/photo.heic")
        runCurrent()

        assertEquals(
            InvalidEntry("Couldn't read that image file — try a PNG or JPEG"),
            vm.navigation.receive(),
        )
    }

    @Test
    fun `a non totp qr reports the reason`() = runTest {
        coEvery { decodeTotpQrImage.invoke(any()) } returns DecodeTotpQrImage.Result.NotTotp

        val vm = newVm()
        vm.onQrImagePicked("/cache/menu.png")
        runCurrent()

        assertEquals(InvalidEntry("That QR code is not a TOTP setup code"), vm.navigation.receive())
    }

    @Test
    fun `a camera scan of a default uri fills the field with the bare secret`() = runTest {
        val vm = newVm()
        vm.onQrScanned("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&digits=6&period=30")
        runCurrent()

        assertEquals("JBSWY3DPEHPK3PXP", vm.totpSeed.value)
    }

    @Test
    fun `a camera scan of a non-totp qr reports the reason and keeps the seed`() = runTest {
        val vm = newVm()
        vm.onTotpSeedChanged("JBSWY3DPEHPK3PXP")
        runCurrent()
        vm.onQrScanned("https://example.com/menu")
        runCurrent()

        assertEquals(InvalidEntry("That QR code is not a TOTP setup code"), vm.navigation.receive())
        assertEquals("JBSWY3DPEHPK3PXP", vm.totpSeed.value)
    }

    @Test
    fun `a second save click while one is in flight is ignored`() = runTest {
        coEvery { addPassword.invoke(any()) } coAnswers {
            delay(5_000)
            true
        }

        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onSaveClick()
        runCurrent()
        vm.onSaveClick()
        runCurrent()

        advanceUntilIdle()
        coVerify(exactly = 1) { addPassword.invoke(any()) }
    }

    @Test
    fun `a rejected save frees the button for the corrected retry`() = runTest {
        val vm = newVm()
        vm.onEntryNameChanged("gmail")
        vm.onTotpSeedChanged("not base32 !!")
        runCurrent()

        vm.onSaveClick()
        runCurrent()
        vm.navigation.receive()
        runCurrent()

        vm.onTotpSeedChanged("JBSWY3DPEHPK3PXP")
        runCurrent()
        vm.onSaveClick()
        runCurrent()

        coVerify(exactly = 1) { addPassword.invoke(any()) }
    }

    @Test
    fun `custom field rows can be removed`() = runTest {
        val vm = newVm()
        vm.onAddCustomField()
        vm.onAddCustomField()
        vm.onCustomFieldLabelChanged(0, "first")
        vm.onCustomFieldLabelChanged(1, "second")
        runCurrent()

        vm.onRemoveCustomField(0)
        runCurrent()

        assertEquals(listOf("second"), vm.customFields.value.map { it.label })
    }
}
