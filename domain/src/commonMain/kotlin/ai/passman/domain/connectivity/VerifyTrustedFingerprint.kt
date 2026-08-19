package ai.passman.domain.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure

/**
 * Gate a sync session on [host] being a paired trusted device. Unknown host -> deny (pairing is an
 * explicit ceremony, never silent TOFU on the data path).
 *
 * The peer's identity is no longer verified by a plaintext pubkey pre-fetch. LAN sync now runs over
 * mutual TLS with SPKI pinning: the handshake itself refuses to connect unless the peer's cert pins
 * to this device's stored fingerprint, binding the whole channel rather than a throwaway fetch that
 * used to be discarded. A wrong-key or MITM peer fails the handshake, surfacing as a transfer error.
 * [fingerprintService] is retained for call-site compatibility but no longer touched here.
 */
@Suppress("UNUSED_PARAMETER")
suspend fun verifyTrustedFingerprint(
    host: String,
    trustedDevices: TrustedDevicesRepository,
    fingerprintService: FingerprintService,
): Outcome<Unit> {
    trustedDevices.getByHost(host)
        ?: return Outcome.Error(
            "host not paired: $host",
            TransferFailure.GeneralTransferFailure,
        )
    return Outcome.Success(Unit)
}
