package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.repository.UserPreferences
import kotlin.time.Clock
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Public, in-memory result of a pairing exchange. It contains exactly the peer's public bundle
 * bytes, the display safety number, and the peer address; private material never enters it.
 *
 * [verifiedViaQr] records that a QR possession proof already bound these two identities to each
 * other, which is what allows the screen to drop the manual safety-number compare. It is set by the
 * two places that can know it — the scanner's own ceremony and [QrPairingSession] on the shower —
 * and defaults to false so an exchange that was never QR-assisted keeps demanding the compare.
 */
class PendingPairing(
    peerBundleBytes: ByteArray,
    val safetyNumber: String,
    val peerAddress: String,
    val verifiedViaQr: Boolean = false,
) {
    val peerBundleBytes: ByteArray = peerBundleBytes.copyOf()
}

/**
 * One short-lived pending pairing, deliberately separate from [ai.passman.domain.connectivity.model.TrustedDevice].
 *
 * `AwaitingConfirmation` is reserved for an established signed pairing whose peer identity became
 * stale; it must never represent this initial handshake. The expiry metadata and the [PairingOwner]
 * stamp are private to this state holder so [PendingPairing] itself contains only public pairing
 * material — the account name in particular never reaches the screen through it.
 *
 * An entry is bound to the owner it was begun under, and [active] only ever hands it back to that
 * owner. That is what stops a confirmation the store refused from being retried under whoever is
 * signed in next: the exchange survives a refused write on purpose, so pressing Confirm again does
 * not cost a whole fresh ceremony, and without the stamp that retained exchange is a replay — the
 * peer material account A attested to, committed into account B's store, which is the pin file the
 * sync authorizer admits inbound peers on.
 */
class PendingPairingState(
    private val nowMs: () -> Long = { Clock.System.now().toEpochMilliseconds() },
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
) {
    private data class ActivePairing(
        val pairing: PendingPairing,
        val owner: PairingOwner,
        val expiresAtMs: Long,
    )

    private val mutex = Mutex()
    private var active: ActivePairing? = null

    suspend fun replace(pairing: PendingPairing, owner: PairingOwner) = mutex.withLock {
        active = ActivePairing(pairing, owner, nowMs() + timeoutMs)
    }

    /**
     * The live exchange, or null once the explicit pairing window has expired or [owner] is not the
     * one that began it.
     *
     * Both answers drop the entry. An expired one is dead by definition; a foreign one is worse
     * than dead, and leaving it in place would keep offering the replay to every account that signs
     * in during its window.
     */
    suspend fun active(owner: PairingOwner): PendingPairing? = mutex.withLock {
        val current = active ?: return@withLock null
        when {
            nowMs() >= current.expiresAtMs -> {
                active = null
                null
            }
            current.owner != owner -> {
                active = null
                null
            }
            else -> current.pairing
        }
    }

    suspend fun clear() = mutex.withLock { active = null }

    companion object {
        const val DEFAULT_TIMEOUT_MS: Long = 5 * 60 * 1_000L
    }
}

/**
 * Exchange public bundles and prepare the locally displayed safety number without persisting a device.
 *
 * With a scanned [Parameters.qr] this is the scanner's half of QR pairing, and it does two extra
 * things. The code commits to an identity, so the bundle fetched from the address in it must digest
 * to what the code said before this device pushes anything back — a code pointing at a machine in
 * the middle fails here, having told that machine nothing. And the push carries a proof that this
 * device saw the code: an HMAC keyed on the code's nonce over both canonical bundles, which is what
 * lets the peer skip the manual compare. Without a code, every byte of this is what it always was.
 */
class BeginDevicePairing(
    private val fingerprintService: FingerprintService,
    private val pendingPairingState: PendingPairingState,
    private val userPreferences: UserPreferences,
) : Usecase<BeginDevicePairing.Parameters, Outcome<PendingPairing>> {
    data class Parameters(
        /**
         * The address to run the exchange against. On a QR ceremony the caller passes
         * [PairingQrPayload.host] verbatim — see [qr].
         */
        val host: String,
        /**
         * The peer's pairing-listener port. On a QR ceremony the caller passes
         * [PairingQrPayload.port] verbatim — see [qr].
         */
        val port: Int = PairingQrPayload.DEFAULT_PAIRING_PORT,
        /**
         * Set when the ceremony was started from a scanned or pasted pairing code.
         *
         * When it is set, [host] and [port] must be the payload's own — the ViewModel passes
         * `payload.host` / `payload.port`. Fetching from one address while checking the digest a
         * code published for another would verify a commitment nobody made about the machine
         * actually being talked to, so the two are required to agree.
         */
        val qr: PairingQrPayload? = null,
    )

    override suspend fun invoke(param: Parameters): Outcome<PendingPairing> {
        // A programmer contract, not user input: a scanned payload carries its own address and the
        // caller holds it, so a disagreement here is a wiring bug rather than anything a scanner or
        // an attacker can provoke. It matters because everything below trusts the two to be one
        // address — fetching from one while checking a digest the code published about another
        // would prove a commitment nobody made about the machine actually on the other end.
        require(param.qr == null || (param.host == param.qr.host && param.port == param.qr.port)) {
            "QR ceremony must target the scanned payload's address"
        }
        // Sampled before the exchange rather than alongside the result: the bundle handed to the
        // peer below is *this* account's identity, so this is the account whose attestation the
        // exchange carries. Sampling it afterwards would stamp whoever the account had become
        // while the fetch and push were in flight, and let that account confirm a ceremony it
        // never took part in.
        val owner = PairingOwner.current(userPreferences)
        val peer = when (val result = fingerprintService.fetchPeerDeviceIdentityBundle(param.host, param.port)) {
            is Outcome.Success -> result.value
            is Outcome.Error -> return result
        }
        // Checked before this device says anything about itself, and in constant time because the
        // answer is about attacker-influenced bytes: whoever answers at that address gets to choose
        // the bundle being digested here.
        if (param.qr != null && !constantTimeEquals(peer.digest(fingerprintService), param.qr.digest)) {
            return Outcome.Error(
                "QR does not match the device at this address — reshow the QR and try again",
                TransferFailure.GeneralTransferFailure,
            )
        }
        val local = when (val result = fingerprintService.getOwnDeviceIdentityBundle()) {
            is Outcome.Success -> result.value
            is Outcome.Error -> return result
        }
        // Own bundle first, the fetched one second. The order is frozen protocol, not taste: the
        // peer rebuilds these same bytes from the other side (QrPairingSession.onInboundBundle,
        // where its own roles are reversed) and a proof over any other ordering will not verify.
        val proof = param.qr?.let { qr ->
            PROOF_BASE64.encode(
                fingerprintService.hmacSha256(
                    key = qr.nonce,
                    data = local.canonicalEncoding() + peer.canonicalEncoding(),
                ),
            )
        }
        when (val result = fingerprintService.pushDeviceIdentityBundle(local, param.host, param.port, proof)) {
            is Outcome.Success -> Unit
            is Outcome.Error -> return result
        }

        val pending = PendingPairing(
            peerBundleBytes = Json.encodeToString(peer).encodeToByteArray(),
            safetyNumber = local.safetyNumber(peer, fingerprintService),
            peerAddress = param.host,
            // The digest above already tied the address to the identity the code committed to, so
            // this side has verified the pairing whatever the peer makes of the proof it just sent.
            verifiedViaQr = param.qr != null,
        )
        pendingPairingState.replace(pending, owner)
        return Outcome.Success(pending)
    }
}
