package ai.passman.viewmodel.sync

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.exception.Failure
import ai.passman.domain.settings.exception.TransferFailure

fun Outcome.Error.toSyncError(): SyncState.Error = SyncState.Error(
    message = friendlyMessage(cause, fallback = message),
    noSavedAddress = cause is TransferFailure.NoSavedAddress,
)

fun friendlyMessage(failure: Failure, fallback: String): String = when (failure) {
    is TransferFailure.NoSavedAddress ->
        "No saved peer IP - set one via Settings > Transfer first."
    is TransferFailure.PeerUnreachable ->
        "Could not reach ${failure.host}. The peer's IP may have changed."
    is TransferFailure.PublicKeyFetchFailure ->
        "Could not fetch peer's public key. Is the peer in Receive mode?"
    is TransferFailure.FingerprintMismatch ->
        "Aborted: ${failure.host} presented a different fingerprint than paired " +
            "device '${failure.deviceName}'. Verify the peer or re-pair from Settings."
    is TransferFailure.PeerSyncTimeout ->
        "Peer at ${failure.host} did not enter sync mode. Tap Sync on the peer device to sync."
    is TransferFailure.SyncCancelled ->
        "Sync cancelled."
    else -> fallback.ifBlank { "Sync failed." }
}
