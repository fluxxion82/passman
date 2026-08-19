package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.repository.UserPreferences
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.serialization.json.Json

/** Persist a user-confirmed bundle as a signed-hybrid pairing; it never writes an in-flight state. */
@OptIn(ExperimentalEncodingApi::class)
class ConfirmDevicePairing(
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val pendingPairingState: PendingPairingState,
    private val userPreferences: UserPreferences,
) : Usecase<ConfirmDevicePairing.Parameters, Outcome<TrustedDevice>> {
    data class Parameters(val deviceName: String)

    override suspend fun invoke(param: Parameters): Outcome<TrustedDevice> {
        if (param.deviceName.isBlank()) {
            return Outcome.Error("device name is required", TransferFailure.GeneralTransferFailure)
        }
        // Only the account that ran the ceremony may commit it. The exchange outlives a refused
        // write so Confirm can be pressed again (see below), and an unstamped exchange makes that
        // retry replayable: press it once as A, have the write refused, sign in as B, press it
        // again, and B's store — the pin file inbound sync is authorized against — is handed the
        // peer keys only A ever attested to. A foreign owner drops the exchange rather than
        // leaving the replay on offer to the next account too.
        //
        // Past this point [owner] *is* the ceremony's stamp, not merely a sample that agreed with
        // it: [PendingPairingState.active] hands the exchange back to the owner it was begun under
        // and to nobody else, so a non-null answer here means the two are equal. That is the value
        // the write below is bound to.
        val owner = PairingOwner.current(userPreferences)
        val pending = pendingPairingState.active(owner)
            ?: return Outcome.Error(
                "pairing expired, was cancelled, or was begun under a different sign-in",
                TransferFailure.GeneralTransferFailure,
            )
        val peer = runCatching {
            Json.decodeFromString<DeviceIdentityBundle>(pending.peerBundleBytes.decodeToString())
        }.getOrElse {
            pendingPairingState.clear()
            return Outcome.Error("pending pairing bundle is invalid", TransferFailure.GeneralTransferFailure)
        }
        // Match strictly by name — the repository's identity key. Matching by lastHost as well
        // would let a brand-new device pairing from a recycled DHCP address inherit an unrelated
        // device's frozen RSA pin, bricking mTLS for the new pair.
        val previous = trustedDevices.getAll().firstOrNull { it.name == param.deviceName }
        val device = TrustedDevice(
            name = param.deviceName,
            // The existing value is a live mTLS SPKI pin and must survive an explicit upgrade.
            fingerprint = previous?.fingerprint ?: fingerprintService.fingerprintOf(peer.rsaSpki),
            lastHost = pending.peerAddress,
            lastSyncedAt = previous?.lastSyncedAt ?: 0L,
            allowedOps = previous?.allowedOps ?: SyncOps.ALL,
            hybridPublicKey = Base64.Default.encode(peer.hybridPublicKey),
            mldsaPublicKey = Base64.Default.encode(peer.mldsaPublicKey),
            identityDigest = fingerprintService.fingerprintOf(peer.canonicalEncoding()),
            pairingSecurity = PairingSecurity.SignedHybridRequired,
        )
        // The ceremony's own owner goes to the store with the write, and the store compares it
        // against the account it resolves under its write lock. Re-sampling "who is signed in"
        // here instead would prove nothing: reading the store and fingerprinting the peer above are
        // suspending work, and a login landing after that check but before the store takes its lock
        // leaves both this check and the store's own entry-versus-lock check agreeing with
        // themselves — two sample-pairs, each blind to the window the other covers — while A's peer
        // material lands in B's store. There is one owner this device may be filed under, it was
        // fixed when the ceremony began, and it is the one the write carries.
        //
        // The store can still refuse — nobody signed in, the account moved away from the ceremony,
        // the encrypted store would not initialise. The peer has already been handed our bundle by
        // then, so calling that a success is how one side ends up trusting a device that does not
        // trust it back, with a "Confirmed" card to say so. Report the failure, and leave the
        // pending exchange alone so the user can confirm again inside its window instead of being
        // sent back through the whole safety-number ceremony. Only that same account can spend it:
        // the exchange is stamped with [owner], so a retry after the account did move is refused
        // above rather than committing A's peer material under B.
        if (!trustedDevices.add(device, owner)) {
            return Outcome.Error(
                "could not save the pairing; the device was not added",
                TransferFailure.GeneralTransferFailure,
            )
        }
        pendingPairingState.clear()
        return Outcome.Success(device)
    }
}
