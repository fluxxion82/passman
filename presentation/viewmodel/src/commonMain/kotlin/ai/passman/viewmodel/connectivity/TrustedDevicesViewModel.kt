package ai.passman.viewmodel.connectivity

import ai.passman.domain.base.invoke
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
import ai.passman.domain.connectivity.QrPairingEvent
import ai.passman.domain.connectivity.RemoveTrustedDevice
import ai.passman.domain.connectivity.UpdateTrustedDeviceOps
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.settings.CopyToClipboard
import ai.passman.domain.settings.GetIpAddress
import ai.passman.domain.settings.StartPairingServer
import ai.passman.domain.settings.StopPairingServer
import ai.passman.viewmodel.base.BaseViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Drives the Trusted Devices screen: the persisted pairings (with their per-device
 * [ai.passman.domain.connectivity.model.PairingSecurity]) and one in-flight mutual
 * safety-number ceremony at a time.
 *
 * The ceremony is symmetric: both sides run [BeginDevicePairing] toward each other, and each side
 * confirms only after the human compared the identical grouped safety number on both screens.
 * Nothing is persisted before [ConfirmDevicePairing]; teardown and cancellation always discard the
 * pending exchange.
 *
 * A pairing code short-circuits the manual compare, never the ceremony. One side shows the code this
 * screen arms through [GeneratePairingQrPayload]; the other scans or pastes it, and the possession
 * proof [BeginDevicePairing] and [ai.passman.domain.connectivity.QrPairingSession] exchange over it
 * is what marks a card `verifiedViaQr` — a claim no untrusted input to this class can make.
 *
 * That code is where the screen rests: [PairingEntryMode.QR] is the default entry, so the QR is
 * armed on screen entry and re-armed on every return to it, with typing an address a toggle away.
 * The possession property is unchanged by that — the nonce is still armed only while the code is
 * actually on screen and still dies on every exit from it; the code is simply visible whenever it is
 * armed, instead of waiting behind a button for a user who has to be told the button exists.
 */
class TrustedDevicesViewModel(
    private val getTrustedDevices: GetTrustedDevices,
    private val removeTrustedDevice: RemoveTrustedDevice,
    private val updateTrustedDeviceOps: UpdateTrustedDeviceOps,
    private val getOwnFingerprint: GetOwnFingerprint,
    private val getIpAddress: GetIpAddress,
    private val beginDevicePairing: BeginDevicePairing,
    private val confirmDevicePairing: ConfirmDevicePairing,
    private val cancelDevicePairing: CancelDevicePairing,
    private val startPairingServer: StartPairingServer,
    private val stopPairingServer: StopPairingServer,
    private val generatePairingQrPayload: GeneratePairingQrPayload,
    private val dismissPairingQr: DismissPairingQr,
    private val observeQrPairingEvents: ObserveQrPairingEvents,
    private val getArmedQrPairing: GetArmedQrPairing,
    private val copyToClipboard: CopyToClipboard,
    private val teardownScope: CoroutineScope = CoroutineScope(Dispatchers.Default),
) : BaseViewModel() {

    /** One in-flight pairing ceremony. Nothing is persisted before [Confirmed]. */
    sealed interface PairingState {
        data object Idle : PairingState

        /**
         * This device is displaying its pairing QR/code, waiting for a peer to scan it.
         *
         * Equality by [code] is hand-written for the same reason [PairingQrPayload] writes its
         * own: the code carries the armed nonce, and a data class would hand it to `toString()`.
         */
        class ShowingQr(val code: String) : PairingState {
            override fun equals(other: Any?): Boolean = other is ShowingQr && code == other.code

            override fun hashCode(): Int = code.hashCode()

            override fun toString(): String = "ShowingQr"
        }

        /** Contacting the peer's pairing listener and exchanging public bundles. */
        data object Fetching : PairingState

        /** Both bundles validated; the human must compare [safetyNumber] on both screens. */
        data class CompareSafetyNumber(
            val safetyNumber: String,
            val peerAddress: String,
            /** True when the QR possession proof already verified both identities — no manual compare. */
            val verifiedViaQr: Boolean = false,
        ) : PairingState

        /** The peer bundle was persisted as a signed-hybrid pairing. */
        data class Confirmed(val deviceName: String) : PairingState

        /** Fetch, validation, timeout, or confirmation failure; the ceremony must be restarted. */
        data class Failed(val message: String) : PairingState
    }

    /**
     * Which pairing entry the screen rests on when no ceremony is running.
     *
     * Sticky for the life of this view model and deliberately not persisted: the QR is the entry
     * that works without the user knowing the peer's address, so every visit starts there, and a
     * device that needed manual entry once is not thereby a device that always will.
     */
    enum class PairingEntryMode { QR, MANUAL }

    private val _entryMode = MutableStateFlow(PairingEntryMode.QR)
    val entryMode: StateFlow<PairingEntryMode> = _entryMode.asStateFlow()

    val devices = MutableStateFlow<List<TrustedDevice>>(emptyList())
    val ownFingerprint = MutableStateFlow<String?>(null)
    val ownIp = MutableStateFlow("")

    val pairAddress = MutableStateFlow("")
    val pairName = MutableStateFlow("")

    /** The explicit "I compared these values" attestation; reset on every new ceremony. */
    val safetyNumberCompared = MutableStateFlow(false)
    val pairingState = MutableStateFlow<PairingState>(PairingState.Idle)

    /**
     * The single in-flight ceremony operation. Begin and Confirm are dropped (not queued) while
     * one is running: a second exchange silently replaces the pending peer bundle in the domain
     * layer, so overlapping operations could persist a bundle the user never attested to.
     * Cancel instead abandons this job — it exists to get out of a hung ceremony.
     */
    private var ceremonyJob: Job? = null

    /**
     * Confirmation stays unavailable until the peer bundle validated, a device name is present, and
     * the comparison was attested — either by the user ticking it, or by a QR possession proof that
     * already bound these two identities to each other, which is the whole point of the code.
     */
    val canConfirm: StateFlow<Boolean> =
        combine(pairingState, pairName, safetyNumberCompared) { state, name, compared ->
            state is PairingState.CompareSafetyNumber && name.isNotBlank() && (state.verifiedViaQr || compared)
        }.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    init {
        viewModelScope.launch {
            getTrustedDevices().collect { devices.value = it }
        }
        viewModelScope.launch {
            ownFingerprint.value = when (val outcome = getOwnFingerprint()) {
                is Outcome.Success -> outcome.value
                is Outcome.Error -> null
            }
        }
        // Show this device's LAN IP so the user can read it off to the peer without leaving the
        // screen (the symmetric ceremony needs each side to enter the other's address).
        viewModelScope.launch { ownIp.value = getIpAddress() }
        // One job for the whole screen-entry sequence, in this order and no other: the plaintext
        // pairing listener opens so a peer can start its half of the ceremony toward us (the
        // TLS-only data server never serves this), the reconcile decides whether this screen
        // already owes the user a card, and only then does the QR default arm a nonce behind that
        // listener. Splitting it would let a second stop/start race this start, and would let the
        // default publish a code over the card the reconcile was about to restore.
        viewModelScope.launch {
            runPreludeStep { startPairingServer() }
            observeQrPairingEvents()
                // The events flow has no replay, so a push that landed while this screen was being
                // recreated was announced to nobody. Asking once the subscription is live — not
                // before it, or the same push could fall in the gap between the two — recovers it.
                .onSubscription {
                    runPreludeStep { recoverArmedQrPairing() }
                    runPreludeStep { autoShowPairingQr() }
                }
                .collect { event ->
                    // An inbound push never speaks for an operation the user started. Publishing
                    // peer B's card over an in-flight exchange with peer A would put B's safety
                    // number on screen while the domain still holds A's pending bundle — the user
                    // would be confirming a device they never saw.
                    if (ceremonyJob?.isActive == true) return@collect
                    when (event) {
                        is QrPairingEvent.VerifiedInbound -> {
                            // Legitimate outside a showing code too: only an armed nonce can
                            // produce this, and closing the dialog is how the user reaches the card.
                            safetyNumberCompared.value = false
                            pairingState.value = PairingState.CompareSafetyNumber(
                                safetyNumber = event.safetyNumber,
                                peerAddress = event.peerAddress,
                                verifiedViaQr = true,
                            )
                        }
                        // Anyone who can reach the plaintext pairing port can provoke this by
                        // pushing a bundle while the code is up, so its address and safety number
                        // are attacker-chosen: this must never become a compare card the user could
                        // confirm, and never prefills the address field. It is a dead end by
                        // construction too — a failed proof arms no pending pairing to confirm.
                        //
                        // It only speaks for the code the user is looking at, either. Once they
                        // moved on, a failed proof that could still replace their state would let
                        // the same attacker wipe a live compare card at will.
                        is QrPairingEvent.ProofFailed -> {
                            if (pairingState.value !is PairingState.ShowingQr) return@collect
                            // The session deliberately keeps the nonce armed through a failed proof
                            // so an honest peer can retry against the code still on screen. This
                            // failure just took that code off screen, so the retry window closed
                            // with it: retire the nonce rather than leave it inviting pushes at a
                            // QR nobody is showing. Reshowing the code arms a fresh one.
                            //
                            // Retirement completes *before* the failure is published, the order
                            // rejectScan documents: the card is the user's cue to dismiss it and
                            // arm a fresh code, and a clear still parked when they take that cue
                            // would land on the fresh nonce and kill it.
                            dismissPairingQr()
                            // Re-read after the suspension for the same reason the guard above
                            // exists: the failure only speaks for the code the user was looking at,
                            // and they may have turned away from it while the clear was in flight.
                            if (pairingState.value !is PairingState.ShowingQr) return@collect
                            pairingState.value = PairingState.Failed(
                                "QR pairing failed verification (attempt from ${event.peerAddress}) — " +
                                    "reshow the QR and scan again, or enter the peer's address manually.",
                            )
                        }
                    }
                }
        }
    }

    /**
     * Run one screen-entry step so a throw out of it cannot outlive the step.
     *
     * All three share the one job the collect below runs on, and the collect is what that job exists
     * for: a screen whose listener pushes reach nobody cannot pair at all, while everything ahead of
     * it only decides what the screen rests on. An unchecked failure — the listener refusing to bind,
     * a payload that cannot be built — must therefore cost the screen its default, not its ears.
     * Failures the use-cases return as [Outcome.Error] are handled where they are returned.
     *
     * Cancellation is rethrown: that one is the scope tearing the whole job down, not a step failing.
     */
    private suspend fun runPreludeStep(step: suspend () -> Unit) {
        runCatching { step() }.onFailure { if (it is CancellationException) throw it }
    }

    /**
     * Adopt a QR-verified exchange the domain is already holding, but only over an [PairingState.Idle]
     * screen: anything else is a live flow this would clobber, and a code reshown for peer B must not
     * be replaced by peer A's stale card.
     */
    private suspend fun recoverArmedQrPairing() {
        if (pairingState.value !is PairingState.Idle) return
        val armed = getArmedQrPairing() ?: return
        safetyNumberCompared.value = false
        pairingState.value = PairingState.CompareSafetyNumber(
            safetyNumber = armed.safetyNumber,
            peerAddress = armed.peerAddress,
            verifiedViaQr = true,
        )
    }

    /**
     * The QR-first default, applied to whatever the reconcile above left standing.
     *
     * Only over [PairingState.Idle]: a recovered card is the pairing the user came back to confirm,
     * and arming a code over it would discard it. The listener it arms behind is the one this same
     * job just opened, so there is deliberately no restart here — a stop/start would race that
     * start, and a listener opened moments ago has spent nothing yet.
     */
    private suspend fun autoShowPairingQr() {
        if (_entryMode.value != PairingEntryMode.QR) return
        if (pairingState.value !is PairingState.Idle) return
        if (ceremonyJob?.isActive == true) return
        // Owned by [ceremonyJob] like every other ceremony operation, so a click that lands while
        // the nonce is being armed is dropped rather than racing it — and awaited here, so the
        // arming stays sequenced inside the one job that opened the listener.
        coroutineScope { ceremonyJob = launch { enterQrDefault() } }
    }

    /**
     * Enter the QR default: arm a nonce and put the code up, or hand the user the manual entry with
     * the reason a code could not be built.
     *
     * The fallback is a mode change rather than a retry on purpose. A device with no usable network
     * address will not grow one by being asked again, so a retry loop would spin behind a dead QR
     * box; flipping to [PairingEntryMode.MANUAL] puts the banner over the address field, which is
     * the one control that can still get the user paired. It stays there until they act.
     */
    private suspend fun enterQrDefault() {
        if (!showGeneratedCode()) _entryMode.value = PairingEntryMode.MANUAL
    }

    /**
     * Publish a freshly armed code, or the reason there is none. Returns whether one could be built.
     *
     * The mode is re-read after the build, not trusted from before it: building a code suspends, and
     * a user who turned to the manual entry while it was in flight would otherwise have the QR put
     * back over the address field they just asked for — their request silently lost to a code that
     * was already on its way. The nonce that build armed goes with the code that is never shown, for
     * the reason every other retirement here exists: a nonce armed behind a code nobody is looking at
     * keeps inviting pushes.
     */
    private suspend fun showGeneratedCode(): Boolean = when (val outcome = generatePairingQrPayload()) {
        is Outcome.Success -> {
            if (_entryMode.value == PairingEntryMode.QR) {
                pairingState.value = PairingState.ShowingQr(outcome.value.encode())
            } else {
                dismissPairingQr()
                pairingState.value = PairingState.Idle
            }
            true
        }
        is Outcome.Error -> {
            pairingState.value = PairingState.Failed(outcome.message)
            false
        }
    }

    /**
     * Land back on whichever pairing entry [entryMode] calls for, once a ceremony is done with.
     *
     * Every exit from a terminal card goes through here, so the QR default is re-entered exactly as
     * the screen first entered it — with a *fresh* nonce. The one the finished (or failed, or
     * cancelled) flow left behind is spent or retired, and reshowing it would advertise a ceremony
     * that cannot complete. The listener restarts for the same reason: it accepts one push per
     * lifecycle, and the flow that just ended may well have been it.
     */
    private suspend fun returnToEntry() {
        pairingState.value = PairingState.Idle
        restartPairingListener()
        if (_entryMode.value == PairingEntryMode.QR) enterQrDefault()
    }

    override fun onCleared() {
        super.onCleared()
        // viewModelScope is already cancelled here, so run teardown on an independent scope to
        // guarantee the pending ceremony is discarded and the plaintext listener actually closes.
        // CancelDevicePairing retires the QR nonce as well, so no separate dismissal is needed —
        // the narrower DismissPairingQr exists for the opposite case, closing the code while
        // deliberately keeping the exchange it raised.
        teardownScope.launch {
            cancelDevicePairing()
            stopPairingServer()
        }
    }

    fun onPairAddressChanged(value: String) {
        pairAddress.value = value
    }

    fun onPairNameChanged(value: String) {
        pairName.value = value
    }

    fun onSafetyNumberComparedChanged(value: Boolean) {
        safetyNumberCompared.value = value
    }

    /**
     * Run our half of the mutual exchange toward the peer. The peer runs the same call toward us;
     * the safety number is order-independent, so both screens display the same value.
     *
     * A pairing code pasted into the address field is the same gesture as scanning one, so it takes
     * the scanned path rather than being dialled as a hostname.
     */
    fun onBeginPairingClick() {
        if (ceremonyJob?.isActive == true) return
        val entered = pairAddress.value
        if (PairingQrPayload.looksLikePairingCode(entered)) {
            onScanResult(entered)
            return
        }
        val host = entered.trim()
        if (host.isBlank()) {
            pairingState.value = PairingState.Failed("Enter the peer's address first.")
            return
        }
        beginPairing(host, qr = null)
    }

    /**
     * Put this device's pairing code on screen and arm the nonce behind it — the way back from
     * manual entry, and the retry after a code could not be built.
     *
     * The listener restarts first: the code invites a push, and arming a nonce behind a listener
     * that has already spent its single accept would advertise a ceremony that cannot complete.
     *
     * Turning away from a compare card discards the exchange behind it rather than abandoning it
     * silently: the pending bundle the user walked away from must not survive to be persisted by
     * whatever confirmation comes next.
     *
     * A failure here leaves the mode on [PairingEntryMode.QR], unlike the automatic path: the user
     * asked for the code, so the answer belongs where they asked, not in a mode they did not pick.
     */
    fun onShowQrClick() {
        if (ceremonyJob?.isActive == true) return
        _entryMode.value = PairingEntryMode.QR
        val abandoned = pairingState.value is PairingState.CompareSafetyNumber
        ceremonyJob = viewModelScope.launch {
            // Answer the click before anything that suspends. Discarding the abandoned exchange,
            // restarting the listener and building the code all take time, the guard above drops
            // every re-tap for the whole of it, and until one of them publishes something the screen
            // still shows the card the user just tapped away from — a tap that did nothing, as far
            // as they can tell. QR-mode [PairingState.Idle] is the code's own card with a spinner
            // where the code will be, so this *is* the progress feedback.
            pairingState.value = PairingState.Idle
            if (abandoned) {
                cancelDevicePairing()
                safetyNumberCompared.value = false
            }
            restartPairingListener()
            showGeneratedCode()
        }
    }

    /**
     * Turn to the manual address entry — the toggle that replaced the QR dialog's dismissal, and the
     * screen's only way out of the QR view now that the code is the resting state.
     *
     * Taking the code off screen retires its nonce with it, exactly as dismissing the dialog did: a
     * nonce left armed behind a code nobody is showing keeps inviting pushes. Unconditionally, like
     * every other retirement here — the state on screen is no evidence about what the session still
     * holds. A failed proof leaves the nonce armed under a [PairingState.Failed] card, and so does a
     * reshow that could not build the next code, so "no QR showing" is not "no nonce armed".
     *
     * Only a showing is *reset*, though. A push that verified while the code was up has already
     * replaced the state with its confirm card, and this is precisely how the user reaches that card
     * — resetting would throw the pairing away — and a ceremony already running is likewise none of
     * this toggle's business.
     */
    fun onEnterManualMode() {
        _entryMode.value = PairingEntryMode.MANUAL
        viewModelScope.launch {
            dismissPairingQr()
            if (pairingState.value is PairingState.ShowingQr) pairingState.value = PairingState.Idle
        }
    }

    /**
     * Copy the displayed pairing code, for a peer with no camera to paste into its address field.
     *
     * Only a code actually on screen is copyable. The code carries the live nonce, so copying
     * whatever some later state still remembers would put an armed code on the clipboard after the
     * screen stopped showing it — and the clipboard is read by everything.
     *
     * The copy goes through the domain use-case rather than the Compose clipboard, so it inherits
     * the platform clipboard policy (expiry, sensitive-content flags) every other copy on this app
     * gets instead of a second, unmanaged path to the same place.
     */
    fun onCopyCodeClick() {
        val showing = pairingState.value as? PairingState.ShowingQr ?: return
        viewModelScope.launch { copyToClipboard(showing.code) }
    }

    /**
     * A scanned or pasted pairing code. The address in the code is the one the ceremony runs
     * against; nothing the user typed is mixed into it.
     *
     * The wording of every rejection lives here rather than in the domain model, which classifies
     * the failure and stays free of English.
     *
     * The in-flight check covers the rejections as well as the exchange: a stray scan of something
     * unparseable must not replace the state of a ceremony that is still running.
     */
    fun onScanResult(text: String) {
        if (ceremonyJob?.isActive == true) return
        when (val parsed = PairingQrPayload.parse(text)) {
            is PairingQrPayload.ParseResult.Parsed -> beginPairing(parsed.payload.host, parsed.payload)
            is PairingQrPayload.ParseResult.NotPairingCode -> rejectScan("Not a Passman pairing code.")
            is PairingQrPayload.ParseResult.Malformed -> rejectScan(
                when (parsed.reason) {
                    PairingQrPayload.ParseResult.Reason.UNSUPPORTED_VERSION ->
                        "Pairing code is from a newer app version — update this device."
                    PairingQrPayload.ParseResult.Reason.INCOMPLETE ->
                        "Pairing code is incomplete — copy or scan the whole code."
                    PairingQrPayload.ParseResult.Reason.INVALID ->
                        "Pairing code is invalid — reshow the QR and try again."
                },
            )
        }
    }

    /**
     * Publish a scan the parser refused — and retire our own nonce on the way past.
     *
     * Scanning is how the user gives up on their own code whether or not the thing they pointed the
     * camera at parsed. A rejection that leaves the nonce armed keeps a code nobody is showing
     * inviting pushes, and the next one to verify raises a confirm card over the failure the user is
     * reading. Dismissal comes first for that reason: the state this publishes is a dead end.
     */
    private fun rejectScan(message: String) {
        viewModelScope.launch {
            dismissPairingQr()
            pairingState.value = PairingState.Failed(message)
        }
    }

    /**
     * The exchange itself, identical either way except for what it can claim afterwards.
     *
     * With a [qr] the address and port are the payload's own — [BeginDevicePairing] requires them to
     * agree, because checking a digest one address published against a bundle fetched from another
     * would verify a commitment nobody made. `verifiedViaQr` is read back off the exchange rather
     * than assumed from `qr != null`: only the use-case knows the digest actually matched.
     */
    private fun beginPairing(host: String, qr: PairingQrPayload?) {
        if (ceremonyJob?.isActive == true) return
        ceremonyJob = viewModelScope.launch {
            // Starting an exchange is how the user gives up on their own code, so retire its nonce
            // as the code comes off screen. Unconditional rather than gated on a showing state: a
            // failed proof leaves the nonce armed under a Failed card, so "no QR on screen" is not
            // the same as "no nonce armed", and only clearing covers both. The session consumes its
            // nonce atomically, so a push already in flight is decided there, not by this ordering.
            dismissPairingQr()
            pairingState.value = PairingState.Fetching
            safetyNumberCompared.value = false
            // The listener accepts exactly one peer push per lifecycle, so it restarts per
            // ceremony — pairing a second device from the same screen visit would 409 otherwise.
            restartPairingListener()
            val outcome = beginDevicePairing(
                BeginDevicePairing.Parameters(
                    host = qr?.host ?: host,
                    port = qr?.port ?: PairingQrPayload.DEFAULT_PAIRING_PORT,
                    qr = qr,
                ),
            )
            // Reset again right before publishing: an attestation must never predate the bundle
            // it gates, even if the checkbox was toggled while the exchange was in flight.
            safetyNumberCompared.value = false
            pairingState.value = when (outcome) {
                is Outcome.Success -> PairingState.CompareSafetyNumber(
                    safetyNumber = outcome.value.safetyNumber,
                    peerAddress = outcome.value.peerAddress,
                    verifiedViaQr = outcome.value.verifiedViaQr,
                )
                is Outcome.Error -> PairingState.Failed(outcome.message)
            }
        }
    }

    /** Persist the compared bundle. Gated on the exact conditions [canConfirm] exposes to the UI. */
    fun onConfirmPairingClick() {
        if (ceremonyJob?.isActive == true) return
        val state = pairingState.value
        val name = pairName.value.trim()
        if (state !is PairingState.CompareSafetyNumber || name.isBlank()) return
        // The same disjunction [canConfirm] publishes, restated because the UI is not the gate.
        if (!state.verifiedViaQr && !safetyNumberCompared.value) return
        ceremonyJob = viewModelScope.launch {
            when (val outcome = confirmDevicePairing(ConfirmDevicePairing.Parameters(name))) {
                is Outcome.Success -> {
                    pairingState.value = PairingState.Confirmed(outcome.value.name)
                    pairAddress.value = ""
                    pairName.value = ""
                    safetyNumberCompared.value = false
                    restartPairingListener()
                }
                // Covers the pending-pairing timeout as well: the expired exchange was discarded
                // and the user must begin a fresh ceremony.
                is Outcome.Error -> pairingState.value = PairingState.Failed(outcome.message)
            }
        }
    }

    /**
     * Discard the pending exchange without persisting anything. [CancelDevicePairing] clears the QR
     * nonce along with it, so a cancel from a displayed code needs nothing extra.
     */
    fun onCancelPairingClick() {
        // Abandon whatever ceremony operation is mid-flight (a hung fetch included) before
        // discarding the exchange; a cancelled begin must never publish its late result.
        ceremonyJob?.cancel()
        ceremonyJob = viewModelScope.launch {
            cancelDevicePairing()
            safetyNumberCompared.value = false
            returnToEntry()
        }
    }

    /**
     * Acknowledge a terminal [PairingState.Confirmed] or [PairingState.Failed] card and go back to
     * the entry — which in QR mode means a freshly armed code, ready for the next device. The failed
     * QR retry story is exactly this: proof failed, banner, dismiss, new code.
     */
    fun onPairingDismissed() {
        // Dropped, not queued, like every other ceremony operation: a terminal card only exists
        // with nothing in flight, so a job here means something else already owns the state — and
        // owns it well enough to publish its own result. Leaving it untouched is the whole handling;
        // writing Idle would blank a screen mid-fetch on the strength of a stale click.
        if (ceremonyJob?.isActive == true) return
        ceremonyJob = viewModelScope.launch { returnToEntry() }
    }

    /**
     * Re-run the ceremony against an already-paired device (legacy upgrade or stale-key
     * re-verification). [ConfirmDevicePairing] preserves the device's frozen mTLS pin, and the
     * existing pairing keeps working untouched until the user explicitly confirms the new one.
     */
    fun onUpgradePairingClick(device: TrustedDevice) {
        pairAddress.value = device.lastHost
        pairName.value = device.name
        onBeginPairingClick()
    }

    fun onRemoveDevice(name: String) {
        viewModelScope.launch { removeTrustedDevice(name) }
    }

    /** Toggle a single sync op for a device on/off, persisting the new allow-set. */
    fun onToggleDeviceOp(device: TrustedDevice, op: String, enabled: Boolean) {
        val next = if (enabled) device.allowedOps + op else device.allowedOps - op
        viewModelScope.launch {
            updateTrustedDeviceOps(UpdateTrustedDeviceOps.Params(device.name, next))
        }
    }

    private suspend fun restartPairingListener() {
        // startPairingServer is a no-op while the listener runs, so a restart must stop it first.
        stopPairingServer()
        startPairingServer()
    }
}
