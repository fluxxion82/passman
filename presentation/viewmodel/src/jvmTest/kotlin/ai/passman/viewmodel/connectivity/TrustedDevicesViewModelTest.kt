package ai.passman.viewmodel.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.BeginDevicePairing
import ai.passman.domain.connectivity.CancelDevicePairing
import ai.passman.domain.connectivity.ConfirmDevicePairing
import ai.passman.domain.connectivity.DismissPairingQr
import ai.passman.domain.connectivity.GeneratePairingQrPayload
import ai.passman.domain.connectivity.GetArmedQrPairing
import ai.passman.domain.connectivity.GetOwnFingerprint
import ai.passman.domain.connectivity.GetTrustedDevices
import ai.passman.domain.connectivity.ObserveQrPairingEvents
import ai.passman.domain.connectivity.PendingPairing
import ai.passman.domain.connectivity.QrPairingEvent
import ai.passman.domain.connectivity.RemoveTrustedDevice
import ai.passman.domain.connectivity.UpdateTrustedDeviceOps
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.StartPairingServer
import ai.passman.domain.settings.StopPairingServer
import ai.passman.domain.settings.exception.TransferFailure
import androidx.lifecycle.ViewModelStore
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.mockk
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

@OptIn(ExperimentalCoroutinesApi::class)
class TrustedDevicesViewModelTest {
    private val getTrustedDevices: GetTrustedDevices = mockk(relaxed = true)
    private val removeTrustedDevice: RemoveTrustedDevice = mockk(relaxed = true)
    private val updateTrustedDeviceOps: UpdateTrustedDeviceOps = mockk(relaxed = true)
    private val getOwnFingerprint: GetOwnFingerprint = mockk(relaxed = true)
    private val getIpAddress: GetIpAddress = mockk(relaxed = true)
    private val beginDevicePairing: BeginDevicePairing = mockk(relaxed = true)
    private val confirmDevicePairing: ConfirmDevicePairing = mockk(relaxed = true)
    private val cancelDevicePairing: CancelDevicePairing = mockk(relaxed = true)
    private val startPairingServer: StartPairingServer = mockk(relaxed = true)
    private val stopPairingServer: StopPairingServer = mockk(relaxed = true)
    private val generatePairingQrPayload: GeneratePairingQrPayload = mockk(relaxed = true)
    private val dismissPairingQr: DismissPairingQr = mockk(relaxed = true)
    private val observeQrPairingEvents: ObserveQrPairingEvents = mockk(relaxed = true)
    private val getArmedQrPairing: GetArmedQrPairing = mockk(relaxed = true)
    private val copyToClipboard: CopyToClipboard = mockk(relaxed = true)

    /** The pairing listener's side of [ObserveQrPairingEvents]; tests push inbound pushes into it. */
    private val qrEvents = MutableSharedFlow<QrPairingEvent>(extraBufferCapacity = 4)

    /**
     * The armed half of [ai.passman.domain.connectivity.QrPairingSession], modelled here because the
     * nonce hygiene tests are about who retires it. The session drops a push with no nonce
     * registered, so an event simulated after the nonce was retired is one the real session would
     * never have emitted — [pushVerifiedInbound] honours that rather than emitting unconditionally.
     */
    private var nonceArmed = false

    /** Advances per generated code, so a regenerated one is visibly not the code it replaced. */
    private var generatedCodes = 0

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        coEvery { getTrustedDevices.invoke(Unit) } returns emptyFlow()
        coEvery { getOwnFingerprint.invoke(Unit) } returns Outcome.Success("AA:BB:CC")
        coEvery { getIpAddress.invoke(Unit) } returns "192.168.1.2"
        coEvery { observeQrPairingEvents.invoke(Unit) } returns qrEvents
        coEvery { getArmedQrPairing.invoke(Unit) } returns null
        // Both use-cases clear the session's nonce in the domain; the model tracks that.
        coEvery { dismissPairingQr.invoke(Unit) } coAnswers { nonceArmed = false }
        coEvery { cancelDevicePairing.invoke(Unit) } coAnswers { nonceArmed = false }
        // The screen is QR-first, so every view model these tests build arms a code on entry —
        // a fixture default rather than a per-test stub, exactly like the session's nonce.
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            nonceArmed = true
            Outcome.Success(qrPayload(nonce = generatedCodes++))
        }
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = TrustedDevicesViewModel(
        getTrustedDevices = getTrustedDevices,
        removeTrustedDevice = removeTrustedDevice,
        updateTrustedDeviceOps = updateTrustedDeviceOps,
        getOwnFingerprint = getOwnFingerprint,
        getIpAddress = getIpAddress,
        beginDevicePairing = beginDevicePairing,
        confirmDevicePairing = confirmDevicePairing,
        cancelDevicePairing = cancelDevicePairing,
        startPairingServer = startPairingServer,
        stopPairingServer = stopPairingServer,
        generatePairingQrPayload = generatePairingQrPayload,
        dismissPairingQr = dismissPairingQr,
        observeQrPairingEvents = observeQrPairingEvents,
        getArmedQrPairing = getArmedQrPairing,
        copyToClipboard = copyToClipboard,
        teardownScope = CoroutineScope(UnconfinedTestDispatcher()),
    )

    private fun pending(host: String = PEER_HOST, verifiedViaQr: Boolean = false) = PendingPairing(
        peerBundleBytes = byteArrayOf(1, 2, 3),
        safetyNumber = SAFETY_NUMBER,
        peerAddress = host,
        verifiedViaQr = verifiedViaQr,
    )

    private fun qrPayload(host: String = QR_HOST, port: Int = QR_PORT, nonce: Int = 0) = PairingQrPayload(
        host = host,
        port = port,
        digest = ByteArray(32) { it.toByte() },
        nonce = ByteArray(32) { (it + 100 + nonce).toByte() },
    )

    /** Stub the pairing code, and arm the nonce [GeneratePairingQrPayload] registers behind it. */
    private fun armPairingCode(payload: PairingQrPayload = qrPayload()) {
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            nonceArmed = true
            Outcome.Success(payload)
        }
    }

    /**
     * Announce a verified inbound push the way the pairing listener would — which is to say only
     * while a nonce is armed, and spending it in the process.
     */
    private suspend fun pushVerifiedInbound(host: String = PEER_HOST) {
        if (!nonceArmed) return
        nonceArmed = false
        qrEvents.emit(QrPairingEvent.VerifiedInbound(SAFETY_NUMBER, host))
    }

    private fun confirmedDevice(name: String, host: String = PEER_HOST) = TrustedDevice(
        name = name,
        fingerprint = "AA:BB",
        lastHost = host,
        hybridPublicKey = "aGk=",
        mldsaPublicKey = "aGk=",
        identityDigest = "11:22",
        pairingSecurity = PairingSecurity.SignedHybridRequired,
    )

    @Test
    fun `screen open starts the pairing listener and surfaces per-device pairing state`() = runTest {
        val legacy = TrustedDevice(name = "Old Phone", fingerprint = "AA", lastHost = "10.0.0.9")
        val upgraded = confirmedDevice("Pixel")
        coEvery { getTrustedDevices.invoke(Unit) } returns flowOf(listOf(legacy, upgraded))

        val vm = newVm()

        coVerify(exactly = 1) { startPairingServer.invoke(Unit) }
        assertEquals(listOf(legacy, upgraded), vm.devices.value)
        assertEquals(PairingSecurity.LegacyRsa, vm.devices.value[0].pairingSecurity)
        assertEquals(PairingSecurity.SignedHybridRequired, vm.devices.value[1].pairingSecurity)
        assertEquals("192.168.1.2", vm.ownIp.value)
        assertEquals("AA:BB:CC", vm.ownFingerprint.value)
    }

    @Test
    fun `begin pairing walks Idle to Fetching to CompareSafetyNumber`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        // The QR default is the resting state now; a manual begin starts from the code on screen.
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        gate.complete(Outcome.Success(pending()))
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertEquals(SAFETY_NUMBER, state.safetyNumber)
        assertEquals(PEER_HOST, state.peerAddress)
    }

    @Test
    fun `begin pairing restarts the listener before contacting the peer`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        // One peer push is accepted per listener lifecycle, so every ceremony needs a fresh one.
        coVerifyOrder {
            startPairingServer.invoke(Unit) // screen open
            stopPairingServer.invoke(Unit) // ceremony restart
            startPairingServer.invoke(Unit)
            beginDevicePairing.invoke(BeginDevicePairing.Parameters(PEER_HOST))
        }
    }

    @Test
    fun `begin pairing with a blank address fails without contacting anything`() = runTest {
        val vm = newVm()
        vm.onPairAddressChanged("   ")
        vm.onBeginPairingClick()

        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        coVerify(exactly = 0) { beginDevicePairing.invoke(any()) }
        coVerify(exactly = 0) { stopPairingServer.invoke(Unit) }
    }

    @Test
    fun `a malformed peer bundle fails the ceremony`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Error("peer bundle is invalid", TransferFailure.GeneralTransferFailure)

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("peer bundle is invalid", state.message)
        assertFalse(vm.canConfirm.value)
        coVerify(exactly = 0) { confirmDevicePairing.invoke(any()) }
    }

    @Test
    fun `confirmation is unavailable until the bundle validates, a name is present, and the user attests`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        // No validated bundle yet: name and attestation alone must not enable confirmation.
        vm.onPairNameChanged("Pixel")
        vm.onSafetyNumberComparedChanged(true)
        assertFalse(vm.canConfirm.value)
        vm.onConfirmPairingClick()
        coVerify(exactly = 0) { confirmDevicePairing.invoke(any()) }

        vm.onPairNameChanged("")
        vm.onSafetyNumberComparedChanged(false)
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertFalse(vm.canConfirm.value)

        vm.onPairNameChanged("Pixel")
        assertFalse(vm.canConfirm.value) // comparison not attested yet
        vm.onConfirmPairingClick()
        coVerify(exactly = 0) { confirmDevicePairing.invoke(any()) }

        vm.onSafetyNumberComparedChanged(true)
        assertTrue(vm.canConfirm.value)
    }

    @Test
    fun `confirm persists the pairing and restarts the listener`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())
        coEvery { confirmDevicePairing.invoke(ConfirmDevicePairing.Parameters("Pixel")) } returns
            Outcome.Success(confirmedDevice("Pixel"))

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onPairNameChanged("Pixel")
        vm.onSafetyNumberComparedChanged(true)
        vm.onConfirmPairingClick()

        val state = assertIs<TrustedDevicesViewModel.PairingState.Confirmed>(vm.pairingState.value)
        assertEquals("Pixel", state.deviceName)
        assertEquals("", vm.pairAddress.value)
        assertEquals("", vm.pairName.value)
        assertFalse(vm.safetyNumberCompared.value)
        // init start + one restart per ceremony boundary (begin, confirm).
        coVerify(exactly = 3) { startPairingServer.invoke(Unit) }
        coVerify(exactly = 2) { stopPairingServer.invoke(Unit) }

        // Acknowledging the card returns to the QR default, ready for the next device.
        vm.onPairingDismissed()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
    }

    @Test
    fun `an expired pairing surfaces as a failure on confirm`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())
        coEvery { confirmDevicePairing.invoke(any()) } returns
            Outcome.Error("pairing expired or cancelled", TransferFailure.GeneralTransferFailure)

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onPairNameChanged("Pixel")
        vm.onSafetyNumberComparedChanged(true)
        vm.onConfirmPairingClick()

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("pairing expired or cancelled", state.message)
    }

    @Test
    fun `cancel discards the ceremony and restarts the listener`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onSafetyNumberComparedChanged(true)
        vm.onCancelPairingClick()

        coVerify(exactly = 1) { cancelDevicePairing.invoke(Unit) }
        // Cancelling drops back to the entry the mode calls for, which is the QR by default.
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertFalse(vm.safetyNumberCompared.value)
        // init start + begin restart + cancel restart.
        coVerify(exactly = 3) { startPairingServer.invoke(Unit) }
        coVerify(exactly = 2) { stopPairingServer.invoke(Unit) }
    }

    @Test
    fun `upgrading a legacy device reruns the ceremony under its existing name`() = runTest {
        val legacy = TrustedDevice(name = "Old Phone", fingerprint = "AA", lastHost = "10.0.0.9")
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending(host = "10.0.0.9"))
        coEvery { confirmDevicePairing.invoke(ConfirmDevicePairing.Parameters("Old Phone")) } returns
            Outcome.Success(confirmedDevice("Old Phone", host = "10.0.0.9"))

        val vm = newVm()
        vm.onUpgradePairingClick(legacy)

        assertEquals("Old Phone", vm.pairName.value)
        assertEquals("10.0.0.9", vm.pairAddress.value)
        coVerify(exactly = 1) { beginDevicePairing.invoke(BeginDevicePairing.Parameters("10.0.0.9")) }
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)

        vm.onSafetyNumberComparedChanged(true)
        vm.onConfirmPairingClick()
        coVerify(exactly = 1) { confirmDevicePairing.invoke(ConfirmDevicePairing.Parameters("Old Phone")) }
        assertIs<TrustedDevicesViewModel.PairingState.Confirmed>(vm.pairingState.value)
    }

    @Test
    fun `a second begin while one is in flight is ignored`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onPairAddressChanged("10.9.9.9")
        vm.onBeginPairingClick() // ignored: the first exchange is still in flight

        coVerify(exactly = 1) { beginDevicePairing.invoke(any()) }

        gate.complete(Outcome.Success(pending()))
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertEquals(PEER_HOST, state.peerAddress)
        coVerify(exactly = 1) { beginDevicePairing.invoke(BeginDevicePairing.Parameters(PEER_HOST)) }
    }

    @Test
    fun `an attestation made before the bundle arrives does not survive it`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onPairNameChanged("Pixel")
        vm.onBeginPairingClick()
        // Attested while still fetching: there is nothing on screen to have compared yet, so this
        // must not carry over to whatever bundle the fetch eventually produces.
        vm.onSafetyNumberComparedChanged(true)

        gate.complete(Outcome.Success(pending()))
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertFalse(vm.safetyNumberCompared.value)
        assertFalse(vm.canConfirm.value)
        vm.onConfirmPairingClick()
        coVerify(exactly = 0) { confirmDevicePairing.invoke(any()) }
    }

    @Test
    fun `begin while a confirmation is in flight is ignored`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())
        val confirmGate = CompletableDeferred<Outcome<TrustedDevice>>()
        coEvery { confirmDevicePairing.invoke(any()) } coAnswers { confirmGate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onPairNameChanged("Pixel")
        vm.onSafetyNumberComparedChanged(true)
        vm.onConfirmPairingClick()
        // A begin here would replace the pending bundle the in-flight confirmation is persisting,
        // so it must be dropped, not queued.
        vm.onBeginPairingClick()
        coVerify(exactly = 1) { beginDevicePairing.invoke(any()) }

        confirmGate.complete(Outcome.Success(confirmedDevice("Pixel")))
        assertIs<TrustedDevicesViewModel.PairingState.Confirmed>(vm.pairingState.value)
    }

    @Test
    fun `a double confirm click persists exactly once`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())
        val confirmGate = CompletableDeferred<Outcome<TrustedDevice>>()
        coEvery { confirmDevicePairing.invoke(any()) } coAnswers { confirmGate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onPairNameChanged("Pixel")
        vm.onSafetyNumberComparedChanged(true)
        vm.onConfirmPairingClick()
        vm.onConfirmPairingClick()

        coVerify(exactly = 1) { confirmDevicePairing.invoke(any()) }
        confirmGate.complete(Outcome.Success(confirmedDevice("Pixel")))
        assertIs<TrustedDevicesViewModel.PairingState.Confirmed>(vm.pairingState.value)
    }

    @Test
    fun `cancelling a hung fetch abandons the ceremony for good`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        vm.onCancelPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        coVerify(exactly = 1) { cancelDevicePairing.invoke(Unit) }

        // The abandoned exchange must not resurface after the user cancelled it.
        gate.complete(Outcome.Success(pending()))
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
    }

    @Test
    fun `screen teardown cancels the pending ceremony and stops the listener`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        val store = ViewModelStore()
        store.put("trusted-devices", vm)
        store.clear()

        coVerifyOrder {
            cancelDevicePairing.invoke(Unit)
            stopPairingServer.invoke(Unit)
        }
    }

    @Test
    fun `showing the pairing code restarts the listener before arming the nonce`() = runTest {
        val payload = qrPayload()
        coEvery { generatePairingQrPayload.invoke(Unit) } returns Outcome.Success(payload)

        val vm = newVm()
        vm.onShowQrClick()

        val state = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertEquals(payload.encode(), state.code)
        // The nonce must only be armed behind a listener that can still accept the peer's push.
        coVerifyOrder {
            startPairingServer.invoke(Unit) // screen open
            stopPairingServer.invoke(Unit)
            startPairingServer.invoke(Unit)
            generatePairingQrPayload.invoke(Unit)
        }
    }

    @Test
    fun `a pairing code that cannot be built fails the ceremony`() = runTest {
        coEvery { generatePairingQrPayload.invoke(Unit) } returns
            Outcome.Error("no network address available", TransferFailure.GeneralTransferFailure)

        val vm = newVm()
        vm.onShowQrClick()

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("no network address available", state.message)
    }

    @Test
    fun `showing the pairing code while a ceremony is in flight is ignored`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onShowQrClick()

        // The one on screen entry and no other: the click found a ceremony running and was dropped.
        coVerify(exactly = 1) { generatePairingQrPayload.invoke(Unit) }
        // And that one is provably the init auto-show — it precedes the exchange the click hit.
        coVerifyOrder {
            generatePairingQrPayload.invoke(Unit)
            beginDevicePairing.invoke(any())
        }
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)
        gate.complete(Outcome.Success(pending()))
    }

    @Test
    fun `leaving the code for manual entry disarms the nonce and returns to Idle`() = runTest {
        val vm = newVm()
        vm.onShowQrClick()
        vm.onEnterManualMode()

        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
    }

    @Test
    fun `leaving the code leaves the confirm card raised underneath it alone`() = runTest {
        val vm = newVm()
        vm.onShowQrClick()
        // The push landed while the code was up: turning to manual entry must not lose its card.
        qrEvents.emit(QrPairingEvent.VerifiedInbound(SAFETY_NUMBER, PEER_HOST))
        vm.onEnterManualMode()

        // Retired all the same. The state this toggle leaves standing says nothing about whether
        // a nonce is still armed, so the retirement cannot be gated on it — here the push already
        // spent the nonce, and the clear is simply a no-op.
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
    }

    @Test
    fun `copying the code hands the displayed code to the domain clipboard`() = runTest {
        val payload = qrPayload()
        armPairingCode(payload)

        val vm = newVm()
        vm.onShowQrClick()
        vm.onCopyCodeClick()

        // The same string the QR encodes, and through the use-case every other copy goes through.
        coVerify(exactly = 1) { copyToClipboard.invoke(payload.encode()) }
    }

    @Test
    fun `copying with no code on screen copies nothing`() = runTest {
        val vm = newVm()
        // Manual entry is the state with no code: the QR default always has one up.
        vm.onEnterManualMode()
        vm.onCopyCodeClick()

        // The code carries a live nonce, so there is nothing to copy once it is off screen.
        coVerify(exactly = 0) { copyToClipboard.invoke(any()) }
    }

    @Test
    fun `a scanned pairing code runs the ceremony against the code's own address`() = runTest {
        val payload = qrPayload()
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Success(pending(host = QR_HOST, verifiedViaQr = true))

        val vm = newVm()
        vm.onScanResult(payload.encode())

        coVerify(exactly = 1) {
            beginDevicePairing.invoke(
                BeginDevicePairing.Parameters(host = QR_HOST, port = QR_PORT, qr = payload),
            )
        }
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        assertEquals(QR_HOST, state.peerAddress)
    }

    @Test
    fun `a pairing code pasted into the address field takes the scanned path`() = runTest {
        val payload = qrPayload()
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Success(pending(host = QR_HOST, verifiedViaQr = true))

        val vm = newVm()
        vm.onPairAddressChanged("  ${payload.encode()}  ")
        vm.onBeginPairingClick()

        coVerify(exactly = 1) {
            beginDevicePairing.invoke(
                BeginDevicePairing.Parameters(host = QR_HOST, port = QR_PORT, qr = payload),
            )
        }
        assertTrue(
            assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value).verifiedViaQr,
        )
    }

    @Test
    fun `scanning something that is not a pairing code contacts nobody`() = runTest {
        val vm = newVm()
        vm.onScanResult("otpauth://totp/Passman:me?secret=ABC")

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Not a Passman pairing code.", state.message)
        coVerify(exactly = 0) { beginDevicePairing.invoke(any()) }
    }

    @Test
    fun `a pairing code from a newer version tells the user to update`() = runTest {
        val vm = newVm()
        vm.onScanResult("passman-pair:v2?host=$QR_HOST&port=$QR_PORT")

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Pairing code is from a newer app version — update this device.", state.message)
        coVerify(exactly = 0) { beginDevicePairing.invoke(any()) }
    }

    @Test
    fun `a truncated pairing code asks for the whole code`() = runTest {
        val vm = newVm()
        vm.onScanResult("passman-pair:v1?host=$QR_HOST")

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Pairing code is incomplete — copy or scan the whole code.", state.message)
        coVerify(exactly = 0) { beginDevicePairing.invoke(any()) }
    }

    @Test
    fun `a corrupt pairing code asks for a fresh one`() = runTest {
        val vm = newVm()
        vm.onScanResult("passman-pair:v1?host=$QR_HOST&port=$QR_PORT&digest=zz&nonce=zz")

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Pairing code is invalid — reshow the QR and try again.", state.message)
        coVerify(exactly = 0) { beginDevicePairing.invoke(any()) }
    }

    @Test
    fun `a verified inbound push raises a confirm card that needs no manual compare`() = runTest {
        coEvery { confirmDevicePairing.invoke(ConfirmDevicePairing.Parameters("Pixel")) } returns
            Outcome.Success(confirmedDevice("Pixel"))

        val vm = newVm()
        qrEvents.emit(QrPairingEvent.VerifiedInbound(SAFETY_NUMBER, PEER_HOST))

        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        assertEquals(SAFETY_NUMBER, state.safetyNumber)
        assertEquals(PEER_HOST, state.peerAddress)
        // The possession proof already did what the checkbox attests to.
        assertFalse(vm.safetyNumberCompared.value)
        assertFalse(vm.canConfirm.value)
        vm.onPairNameChanged("Pixel")
        assertTrue(vm.canConfirm.value)

        vm.onConfirmPairingClick()
        coVerify(exactly = 1) { confirmDevicePairing.invoke(ConfirmDevicePairing.Parameters("Pixel")) }
        assertIs<TrustedDevicesViewModel.PairingState.Confirmed>(vm.pairingState.value)
    }

    @Test
    fun `a failed proof never becomes a confirm card or a prefilled address`() = runTest {
        coEvery { generatePairingQrPayload.invoke(Unit) } returns Outcome.Success(qrPayload())

        val vm = newVm()
        vm.onShowQrClick()
        // Anyone on the LAN can provoke this by pushing garbage at the open listener, so every
        // field it carries is attacker-chosen.
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))

        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals(
            "QR pairing failed verification (attempt from 10.0.0.66) — reshow the QR and scan " +
                "again, or enter the peer's address manually.",
            state.message,
        )
        assertEquals("", vm.pairAddress.value)
        assertFalse(vm.canConfirm.value)
    }

    @Test
    fun `a failed proof never takes down a live compare card`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        val card = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)

        // The user moved on from the code to a manual ceremony. A LAN attacker who can still
        // provoke a failed proof must not be able to wipe the card the user is comparing —
        // repeating that at will would be a pairing denial of service.
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))

        assertEquals(card, vm.pairingState.value)
    }

    @Test
    fun `a verified inbound push never clobbers an in-flight ceremony`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        // Peer B pushes while our own exchange with peer A is still running. Publishing B's card
        // over it would show the user one device's safety number while the domain holds the
        // other's pending bundle — a confirmation for a device they never saw.
        qrEvents.emit(QrPairingEvent.VerifiedInbound(OTHER_SAFETY_NUMBER, "10.0.0.66"))
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        gate.complete(Outcome.Success(pending()))
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertEquals(SAFETY_NUMBER, state.safetyNumber)
        assertEquals(PEER_HOST, state.peerAddress)
    }

    @Test
    fun `scanning while our own code is up retires its nonce`() = runTest {
        coEvery { generatePairingQrPayload.invoke(Unit) } returns Outcome.Success(qrPayload(host = OWN_QR_HOST))
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Success(pending(host = QR_HOST, verifiedViaQr = true))

        val vm = newVm()
        vm.onShowQrClick()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        // The user gave up waiting and scanned the peer instead. Our own nonce must not stay
        // armed behind a code nobody is looking at any more.
        vm.onScanResult(qrPayload().encode())

        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertEquals(QR_HOST, state.peerAddress)
    }

    @Test
    fun `a rejected scan retires our own nonce, so a later push raises nothing`() = runTest {
        armPairingCode()

        val vm = newVm()
        vm.onShowQrClick()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        // Pointing the scanner at the wrong thing is still the user turning away from their own
        // code, so the rejection must retire the nonce exactly like a successful scan does.
        vm.onScanResult("otpauth://totp/Passman:me?secret=ABC")
        val rejected = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Not a Passman pairing code.", rejected.message)

        // A nonce left armed behind a code nobody is showing keeps inviting pushes, and this is
        // what the next one does: a confirm card raised with no ceremony in progress, for a
        // pairing the user abandoned when they turned the scanner on something else.
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
    }

    @Test
    fun `a malformed scan retires our own nonce as well`() = runTest {
        armPairingCode()

        val vm = newVm()
        vm.onShowQrClick()
        vm.onScanResult("passman-pair:v1?host=$QR_HOST")

        val rejected = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("Pairing code is incomplete — copy or scan the whole code.", rejected.message)
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }

        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
    }

    @Test
    fun `a failed proof takes the code off screen and retires its nonce with it`() = runTest {
        armPairingCode()

        val vm = newVm()
        vm.onShowQrClick()
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))

        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        // The session keeps a nonce armed through a failed proof so an honest peer can retry
        // against the code — but the code is off screen now, so that retry window is over. The
        // user reshows the QR to get a fresh one.
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }

        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
    }

    @Test
    fun `a failed proof retires the nonce before it publishes the failure`() = runTest {
        val retired = CompletableDeferred<Unit>()
        coEvery { dismissPairingQr.invoke(Unit) } coAnswers {
            retired.await()
            nonceArmed = false
        }

        val vm = newVm()
        val armed = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))

        // The retirement is in flight, and until it lands the code is still what the screen shows.
        // That is the ordering: the Failed card is the user's cue to dismiss it and arm a fresh
        // code, so a clear still parked when they take that cue would land on the fresh nonce.
        assertEquals(armed, vm.pairingState.value)

        retired.complete(Unit)
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        // The code armed by the dismissal is therefore behind the clear, not in front of it.
        vm.onPairingDismissed()
        val reshown = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertNotEquals(armed.code, reshown.code)
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `a manual begin after a failed QR retires the nonce unconditionally`() = runTest {
        armPairingCode()
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onShowQrClick()
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        // Once as the failure took the code off screen, and again as the exchange begins: the
        // dismissal cannot be conditional on a showing state, because a nonce outlives it.
        coVerify(exactly = 2) { dismissPairingQr.invoke(Unit) }
        coVerifyOrder {
            dismissPairingQr.invoke(Unit)
            beginDevicePairing.invoke(BeginDevicePairing.Parameters(PEER_HOST))
        }
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `a garbage scan during an in-flight ceremony leaves it alone`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        vm.onScanResult("otpauth://totp/Passman:me?secret=ABC")
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        gate.complete(Outcome.Success(pending()))
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `showing the code over a live compare card discards the pending exchange`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())
        coEvery { generatePairingQrPayload.invoke(Unit) } returns Outcome.Success(qrPayload())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)

        vm.onShowQrClick()

        // Leaving the abandoned bundle pending would let the next confirmation persist it.
        coVerifyOrder {
            cancelDevicePairing.invoke(Unit)
            generatePairingQrPayload.invoke(Unit)
        }
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
    }

    @Test
    fun `a push that landed during a screen recreation is recovered on init`() = runTest {
        coEvery { getArmedQrPairing.invoke(Unit) } returns pending(verifiedViaQr = true)

        val vm = newVm()

        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        assertEquals(SAFETY_NUMBER, state.safetyNumber)
        assertEquals(PEER_HOST, state.peerAddress)
    }

    @Test
    fun `the recovered pairing never replaces a code already back on screen`() = runTest {
        val subscribed = CompletableDeferred<Unit>()
        coEvery { observeQrPairingEvents.invoke(Unit) } coAnswers {
            subscribed.await()
            qrEvents
        }
        coEvery { getArmedQrPairing.invoke(Unit) } returns pending(verifiedViaQr = true)
        coEvery { generatePairingQrPayload.invoke(Unit) } returns Outcome.Success(qrPayload())

        val vm = newVm()
        vm.onShowQrClick()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        // The reconcile finally runs, but peer A's stale card must not take down peer B's code.
        subscribed.complete(Unit)
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
    }

    @Test
    fun `a manually entered address still runs the unassisted ceremony`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()

        coVerify(exactly = 1) {
            beginDevicePairing.invoke(
                BeginDevicePairing.Parameters(
                    host = PEER_HOST,
                    port = PairingQrPayload.DEFAULT_PAIRING_PORT,
                    qr = null,
                ),
            )
        }
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertFalse(state.verifiedViaQr)
        // Nothing proved possession here, so the human still has to.
        vm.onPairNameChanged("Pixel")
        assertFalse(vm.canConfirm.value)
        vm.onConfirmPairingClick()
        coVerify(exactly = 0) { confirmDevicePairing.invoke(any()) }
        vm.onSafetyNumberComparedChanged(true)
        assertTrue(vm.canConfirm.value)
    }

    @Test
    fun `the pairing entry starts in QR mode`() = runTest {
        val vm = newVm()

        assertEquals(TrustedDevicesViewModel.PairingEntryMode.QR, vm.entryMode.value)
    }

    @Test
    fun `screen entry puts this device's code on screen without a click`() = runTest {
        val vm = newVm()

        val state = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertEquals(qrPayload().encode(), state.code)
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.QR, vm.entryMode.value)
        // One init job, in order: the nonce is armed behind the listener this same job opened, and
        // nothing restarts that listener underneath — a second stop/start would race the start.
        coVerifyOrder {
            startPairingServer.invoke(Unit)
            generatePairingQrPayload.invoke(Unit)
        }
        coVerify(exactly = 1) { startPairingServer.invoke(Unit) }
        coVerify(exactly = 0) { stopPairingServer.invoke(Unit) }
    }

    @Test
    fun `a recovered pairing wins over the QR default on screen entry`() = runTest {
        coEvery { getArmedQrPairing.invoke(Unit) } returns pending(verifiedViaQr = true)

        val vm = newVm()

        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        // Arming a fresh code over the recovered card would throw away the pairing the user came
        // back to confirm, so the default only applies where the reconcile left Idle standing.
        coVerify(exactly = 0) { generatePairingQrPayload.invoke(Unit) }
    }

    @Test
    fun `a code that cannot be built on entry drops the user into manual entry`() = runTest {
        coEvery { generatePairingQrPayload.invoke(Unit) } returns
            Outcome.Error("no network address available", TransferFailure.GeneralTransferFailure)

        val vm = newVm()

        // No dead QR box: the banner belongs over the address field the user can actually act on.
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)
        val state = assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
        assertEquals("no network address available", state.message)
        // And it stays there — a retry loop against an address that does not exist yet is spin.
        coVerify(exactly = 1) { generatePairingQrPayload.invoke(Unit) }
    }

    @Test
    fun `entering manual mode retires the nonce and takes the code off screen`() = runTest {
        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        vm.onEnterManualMode()

        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        // A nonce left armed behind a code nobody is showing keeps inviting pushes.
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
    }

    @Test
    fun `entering manual mode retires the nonce still armed under a failed card`() = runTest {
        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        // The reshow could not build a code, so a Failed card replaced the one on screen — but a
        // failure to build the next nonce does nothing to the one already armed behind the last.
        coEvery { generatePairingQrPayload.invoke(Unit) } returns
            Outcome.Error("no network address available", TransferFailure.GeneralTransferFailure)
        vm.onShowQrClick()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        vm.onEnterManualMode()

        // "No code on screen" is not "no nonce armed", so the toggle must not gate the retirement
        // on a showing state: the leak it would leave is a live nonce under a card the user is
        // reading, inviting pushes at a QR nobody can see.
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)
    }

    @Test
    fun `entering manual mode leaves a live compare card alone`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        val card = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)

        // The toggle chooses what the *entry* looks like; it never speaks for a running ceremony.
        vm.onEnterManualMode()

        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)
        assertEquals(card, vm.pairingState.value)
    }

    @Test
    fun `showing the code switches the entry mode back to QR`() = runTest {
        val vm = newVm()
        vm.onEnterManualMode()
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)

        vm.onShowQrClick()

        assertEquals(TrustedDevicesViewModel.PairingEntryMode.QR, vm.entryMode.value)
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
    }

    @Test
    fun `showing the code clears the failed card before the new one is built`() = runTest {
        val vm = newVm()
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        // The reshow is not instant — it restarts the listener and builds a fresh code — and the
        // guard drops every re-tap for the whole of it.
        val armed = CompletableDeferred<Outcome<PairingQrPayload>>()
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            nonceArmed = true
            armed.await()
        }

        vm.onShowQrClick()

        // So the click has to answer itself: QR-mode Idle is the code's own card with a spinner
        // where the code will be. Leaving the failure standing would look like the tap did nothing.
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.QR, vm.entryMode.value)

        armed.complete(Outcome.Success(qrPayload(nonce = 9)))
        val state = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertEquals(qrPayload(nonce = 9).encode(), state.code)
    }

    @Test
    fun `a turn to manual entry while the code is being built is not overtaken by it`() = runTest {
        val armed = CompletableDeferred<Outcome<PairingQrPayload>>()
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            nonceArmed = true
            armed.await()
        }

        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)

        // The user asked for the address field while the entry's own code was still being built.
        vm.onEnterManualMode()
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)

        armed.complete(Outcome.Success(qrPayload()))

        // The build lost the race it started, so it publishes nothing: putting the code up now
        // would take back the entry the user asked for, and the request would be lost with it.
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, vm.entryMode.value)
        // And the nonce it armed on the way past goes with the code that was never shown — once as
        // the toggle ran, and again for the one armed behind it. A nonce left over from a code
        // nobody ever saw keeps inviting pushes.
        coVerify(exactly = 2) { dismissPairingQr.invoke(Unit) }
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
    }

    @Test
    fun `dismissing a failed QR card comes back with a freshly armed code`() = runTest {
        val vm = newVm()
        val first = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        qrEvents.emit(QrPairingEvent.ProofFailed(SAFETY_NUMBER, "10.0.0.66"))
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        vm.onPairingDismissed()

        // The failure retired the old nonce on its way out, so the retry has to be a new code
        // entirely — reshowing the spent one would advertise a ceremony that cannot complete.
        val reshown = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertNotEquals(first.code, reshown.code)
    }

    @Test
    fun `cancelling a ceremony lands back on a freshly armed code`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns Outcome.Success(pending())

        val vm = newVm()
        val first = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        vm.onCancelPairingClick()

        val reshown = assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)
        assertNotEquals(first.code, reshown.code)
    }

    @Test
    fun `in manual mode a dismissal rests on the empty entry`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Error("peer bundle is invalid", TransferFailure.GeneralTransferFailure)

        val vm = newVm()
        vm.onEnterManualMode()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Failed>(vm.pairingState.value)

        vm.onPairingDismissed()

        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
        // Only the code the screen opened with: manual mode never arms another one behind the user.
        coVerify(exactly = 1) { generatePairingQrPayload.invoke(Unit) }
    }

    @Test
    fun `a dismissal during a ceremony leaves the state to whoever owns it`() = runTest {
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        // A terminal card only exists with nothing in flight, so a dismissal that finds a ceremony
        // running is a stale click against a state someone else owns — blanking the screen
        // mid-fetch would drop the user somewhere the running exchange never agreed to leave them.
        vm.onPairingDismissed()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        gate.complete(Outcome.Success(pending()))
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `a fresh view model starts QR-first`() = runTest {
        val first = newVm()
        first.onEnterManualMode()
        assertEquals(TrustedDevicesViewModel.PairingEntryMode.MANUAL, first.entryMode.value)

        // Nothing was written anywhere, so the next visit to the screen is QR-first again.
        val second = newVm()

        assertEquals(TrustedDevicesViewModel.PairingEntryMode.QR, second.entryMode.value)
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(second.pairingState.value)
    }

    @Test
    fun `scanning from the auto-shown code still begins the ceremony`() = runTest {
        coEvery { beginDevicePairing.invoke(any()) } returns
            Outcome.Success(pending(host = QR_HOST, verifiedViaQr = true))

        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.ShowingQr>(vm.pairingState.value)

        vm.onScanResult(qrPayload(nonce = 7).encode())

        // The ceremony's unconditional dismissal is what retires the nonce nobody clicked to arm.
        coVerify(exactly = 1) { dismissPairingQr.invoke(Unit) }
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertEquals(QR_HOST, state.peerAddress)
        assertTrue(state.verifiedViaQr)
        pushVerifiedInbound()
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `the QR default is dropped, not queued, behind an in-flight ceremony`() = runTest {
        val subscribed = CompletableDeferred<Unit>()
        coEvery { observeQrPairingEvents.invoke(Unit) } coAnswers {
            subscribed.await()
            qrEvents
        }
        val gate = CompletableDeferred<Outcome<PendingPairing>>()
        coEvery { beginDevicePairing.invoke(any()) } coAnswers { gate.await() }

        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)
        vm.onPairAddressChanged(PEER_HOST)
        vm.onBeginPairingClick()
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)

        // The default finally gets its turn, mid-ceremony. Arming a nonce here would hand the
        // listener the running exchange owns to a second peer, so it is dropped rather than queued.
        subscribed.complete(Unit)

        coVerify(exactly = 0) { generatePairingQrPayload.invoke(Unit) }
        assertIs<TrustedDevicesViewModel.PairingState.Fetching>(vm.pairingState.value)
        gate.complete(Outcome.Success(pending()))
        assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
    }

    @Test
    fun `a push announced while the screen is still arming its code is not lost`() = runTest {
        val armed = CompletableDeferred<Outcome<PairingQrPayload>>()
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            nonceArmed = true
            armed.await()
        }

        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)

        // The subscription is live before the arming runs — that is what onSubscription buys — so
        // a push announced during that window has a buffer to land in rather than a gap to fall
        // through. The events flow has no replay, so anything lost here is lost for good.
        qrEvents.emit(QrPairingEvent.VerifiedInbound(SAFETY_NUMBER, PEER_HOST))
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)

        armed.complete(Outcome.Success(qrPayload()))
        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        assertEquals(PEER_HOST, state.peerAddress)
    }

    @Test
    fun `an auto-show that throws does not take the event collector down with it`() = runTest {
        coEvery { generatePairingQrPayload.invoke(Unit) } coAnswers {
            // The session registered the nonce before the payload build blew up, so the listener
            // can still verify a push against it — which is exactly why this must not be fatal.
            nonceArmed = true
            throw IllegalStateException("no network interface")
        }

        val vm = newVm()
        assertIs<TrustedDevicesViewModel.PairingState.Idle>(vm.pairingState.value)

        // Receiving this is what the screen is for. A prelude step that threw shares the job with
        // the collector, so it must not be allowed to unsubscribe it on the way out.
        pushVerifiedInbound()

        val state = assertIs<TrustedDevicesViewModel.PairingState.CompareSafetyNumber>(vm.pairingState.value)
        assertTrue(state.verifiedViaQr)
        assertEquals(PEER_HOST, state.peerAddress)
    }

    private companion object {
        const val PEER_HOST = "10.0.0.7"
        const val QR_HOST = "10.0.0.8"
        const val OWN_QR_HOST = "10.0.0.5"
        const val QR_PORT = 2325
        const val SAFETY_NUMBER = "12345 67890 12345 67890 12345"
        const val OTHER_SAFETY_NUMBER = "99999 88888 77777 66666 55555"
    }
}
