package ai.passman.domain.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.service.FingerprintService
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** What an inbound QR-pairing push turned out to be, for the Trusted Devices screen to react to. */
sealed interface QrPairingEvent {
    /**
     * The proof verified: whoever pushed this bundle had seen the QR on this screen, and the bundle
     * they pushed is the one the proof was computed over. The manual compare is redundant, and the
     * safety number rides along only so the screen can still show it.
     */
    data class VerifiedInbound(val safetyNumber: String, val peerAddress: String) : QrPairingEvent

    /**
     * A push arrived while the QR was on screen but its proof did not hold up — an old app that
     * never sends one, a stale QR, a re-scan of a code this device has already spent, or someone on
     * the network trying their luck. Nothing is armed; the humans fall back to comparing numbers.
     */
    data class ProofFailed(val safetyNumber: String, val peerAddress: String) : QrPairingEvent
}

/**
 * The nonce behind a displayed pairing QR, and the verification of the push it invites.
 *
 * The QR carries a random nonce that never leaves this device except on that screen. A peer that
 * scanned it can key an HMAC on it over both canonical identity bundles; nobody who only reached the
 * plaintext pairing port can. So a proof that verifies is a possession proof — evidence the peer
 * physically saw this screen — and it is what lets the ceremony skip the 25-digit compare that
 * otherwise carries the whole burden of proving there is no machine in the middle. Because the proof
 * covers both bundles, it also binds that possession to *these two identities*: an attacker who
 * relays a scanned code cannot swap in its own bundle without invalidating the proof.
 *
 * Three properties keep that argument honest, and each is a line of code below:
 *
 * - **Only while the QR is up.** With no nonce registered, an inbound push is dropped exactly as it
 *   was before QR pairing existed — arming a pending pairing from an unsolicited push is precisely
 *   the attack the pairing listener has always refused.
 * - **Constant-time comparison.** The proof is attacker-supplied input arriving on an unauthenticated
 *   port. A comparison that returns early on the first differing byte leaks how much of a guess was
 *   right, which is a forgery oracle for an attacker who can push repeatedly.
 * - **One nonce, one pairing.** A verified proof consumes the nonce, so a replay of the same push —
 *   captured off the wire, or the same code scanned twice — finds nothing armed and is dropped. A
 *   *failed* proof does not consume it: the QR is still on screen and an honest peer deserves a
 *   retry against it.
 *
 * The bundle bytes themselves are never trusted before they parse, and a bundle that parses is still
 * only public material: the pending pairing this arms is confirmed by a human pressing Confirm, and
 * it is stamped with the [PairingOwner] the QR was shown under so no other account can spend it.
 */
class QrPairingSession(
    private val fingerprintService: FingerprintService,
    private val pendingPairingState: PendingPairingState,
) {
    private val mutex = Mutex()
    private var nonce: ByteArray? = null
    private var owner: PairingOwner? = null

    // Dropping the oldest event beats suspending: emit() runs on the pairing listener's handler, and
    // a Trusted Devices screen that stopped collecting must not be able to stall the transport.
    private val _events = MutableSharedFlow<QrPairingEvent>(
        extraBufferCapacity = EVENT_BUFFER,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<QrPairingEvent> = _events.asSharedFlow()

    /**
     * Arm the session for the QR now going on screen. At most one nonce is live at a time, so
     * reshowing the code retires the previous one rather than leaving two codes acceptable.
     */
    suspend fun register(nonce: ByteArray, owner: PairingOwner) = mutex.withLock {
        this.nonce = nonce.copyOf()
        this.owner = owner
    }

    /** Disarm: the QR came off screen, so pushes go back to being dropped. */
    suspend fun clear() = mutex.withLock {
        nonce = null
        owner = null
    }

    /**
     * Handle a bundle pushed to the plaintext pairing listener.
     *
     * Everything here is attacker-reachable, so the order matters: nothing is armed and nothing is
     * even said out loud until a nonce is registered and the pushed bytes parse as an identity
     * bundle. Silence is the correct answer to a push this device did not invite — reporting it
     * would let anyone on the network raise a pairing card on a screen nobody asked to pair from.
     *
     * @return true only when the proof verified *and* this call is the one that spent the nonce, so
     *   a pending pairing is armed as a result of it. Every other path returns false: no QR on
     *   screen, bytes that do not parse, no local identity to compare against, a proof that did not
     *   hold up, and — the case a caller cannot see any other way — a concurrent push that consumed
     *   the same nonce first. Callers with a single accept to spend must spend it only on true.
     */
    suspend fun onInboundBundle(bundleBytes: ByteArray, proofBase64Url: String?, remoteHost: String): Boolean {
        val (activeNonce, activeOwner) = mutex.withLock {
            (nonce ?: return false) to (owner ?: return false)
        }
        val peer = runCatching {
            Json.decodeFromString<DeviceIdentityBundle>(bundleBytes.decodeToString())
        }.getOrElse { return false }
        val own = when (val result = fingerprintService.getOwnDeviceIdentityBundle()) {
            is Outcome.Success -> result.value
            is Outcome.Error -> return false
        }
        val safetyNumber = own.safetyNumber(peer, fingerprintService)
        // Both canonical encodings, peer first: the same bytes the scanner signed, in the order
        // BeginDevicePairing writes them (its own bundle, then the one it fetched from here).
        val expected = fingerprintService.hmacSha256(
            key = activeNonce,
            data = peer.canonicalEncoding() + own.canonicalEncoding(),
        )
        val presented = proofBase64Url?.let { runCatching { PROOF_BASE64.decode(it) }.getOrNull() }
        if (presented == null || !constantTimeEquals(expected, presented)) {
            _events.emit(QrPairingEvent.ProofFailed(safetyNumber, remoteHost))
            return false
        }
        // Check and consume in one critical section, and let its answer decide whether this call
        // continues at all. Reading the nonce and retiring it under two separate locks would let two
        // pushes that both verified against it each arm a pairing and each announce one; here the
        // loser of the swap consumed nothing and stops before replace() and before any event.
        //
        // The swap also matches on the nonce this push was verified against rather than on "some
        // nonce is present", so it cannot silently retire a fresher code the user reshowed while
        // this push was in flight.
        val consumed = mutex.withLock {
            if (nonce?.contentEquals(activeNonce) == true) {
                nonce = null
                owner = null
                true
            } else {
                false
            }
        }
        if (!consumed) return false
        pendingPairingState.replace(
            PendingPairing(
                // Re-encode what parsed instead of filing the wire bytes, exactly as
                // BeginDevicePairing does. Whoever reads this pairing later must see the bundle the
                // proof was verified over, not a second parse of attacker-shaped bytes that a
                // different decoder — or a different version of this one — could read differently.
                peerBundleBytes = Json.encodeToString(peer).encodeToByteArray(),
                safetyNumber = safetyNumber,
                peerAddress = remoteHost,
                verifiedViaQr = true,
            ),
            activeOwner,
        )
        _events.emit(QrPairingEvent.VerifiedInbound(safetyNumber, remoteHost))
        return true
    }

    private companion object {
        const val EVENT_BUFFER = 4
    }
}
