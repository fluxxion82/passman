package ai.passman.domain.settings

import ai.passman.domain.exception.Failure
import ai.passman.domain.settings.exception.TransferFailure

/**
 * The human-readable reason behind a sync [Failure].
 *
 * Lives in `domain` rather than in a UI layer because it has no UI dependency to begin with — it
 * maps two domain types ([Failure], [TransferFailure]) to a [String] — and because
 * [ai.passman.domain.settings.RecordSyncOutcome] needs the exact same text for a logged failure's
 * `detail` that the live snackbar showed the user at the time
 * (`ai.passman.viewmodel.sync.SyncState.Error`, via `toSyncError`). Domain code cannot depend on
 * `presentation/viewmodel` — that would invert the module graph — so this had to move down to
 * where both callers can reach it, not be duplicated between them.
 */
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
