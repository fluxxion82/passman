package ai.passman.domain.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure

/**
 * Gate a sync session on [device] still being a paired trusted device. Unknown device -> deny
 * (pairing is an explicit ceremony, never silent TOFU on the data path).
 *
 * The check is on [TrustedDevice.name] — the store's identity key — against the record the user
 * actually chose, not on a fresh address lookup. Nothing stops two pairings from holding the same
 * `lastHost` (re-pairing the same physical peer under a new name produces exactly that), so a
 * by-host lookup here could clear the session on the strength of a *different* record than the one
 * every later step of the session goes on to use. Checking the chosen record is the only reading
 * that matches what is about to be pinned, stamped and logged.
 *
 * What comes back is the record as **stored**, matched by name, not the caller's copy. The caller's
 * copy was read when the chooser was populated and can be older than the store by however long the
 * dialog sat open — and `pairingSecurity` is exactly the field that changes underneath it, when a
 * peer's keys are marked for re-verification. Dispatching a session on a stale copy of that field
 * would skip a refusal the store had already decided on, so the session runs on the returned value
 * and the name is all the caller's copy is really needed for.
 *
 * The peer's identity is no longer verified by a plaintext pubkey pre-fetch. LAN sync now runs over
 * mutual TLS with SPKI pinning: the handshake itself refuses to connect unless the peer's cert pins
 * to this device's stored fingerprint, binding the whole channel rather than a throwaway fetch that
 * used to be discarded. A wrong-key or MITM peer fails the handshake, surfacing as a transfer error.
 * [fingerprintService] is retained for call-site compatibility but no longer touched here.
 */
@Suppress("UNUSED_PARAMETER")
suspend fun verifyTrustedFingerprint(
    device: TrustedDevice,
    trustedDevices: TrustedDevicesRepository,
    fingerprintService: FingerprintService,
): Outcome<TrustedDevice> {
    val stored = trustedDevices.getAll().firstOrNull { it.name == device.name }
        ?: return Outcome.Error(
            "device not paired: ${device.name}",
            TransferFailure.GeneralTransferFailure,
        )
    return Outcome.Success(stored)
}
