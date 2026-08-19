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
        if (failure.reachedPeer) {
            // The push landed before the pull retries ran out the clock - "did not enter sync
            // mode" would be false here, so this falls back to whatever accurate message
            // runSyncSession built instead of hardcoding one that ignores reachedPeer entirely.
            // In production runSyncSession always supplies that message, so this branch is a
            // defensive backstop, not a live path - but it still has to say the same thing
            // runSyncSession does, hence the shared peerReachedTimeoutMessage below rather than a
            // second copy of the sentence that could quietly drift from the first.
            fallback.ifBlank { peerReachedTimeoutMessage(failure.host) }
        } else {
            "Peer at ${failure.host} did not enter sync mode. Tap Sync on the peer device to sync."
        }
    is TransferFailure.SyncCancelled ->
        "Sync cancelled."
    else -> fallback.ifBlank { "Sync failed." }
}

/**
 * The message for a [TransferFailure.PeerSyncTimeout] whose push reached the peer before the pull
 * retries ran out the shared deadline - the peer's server demonstrably came up, so our vault may
 * already be sitting on it. [runSyncSession] builds this exact text for the
 * [ai.passman.domain.settings.model.SyncSessionState.Error] it emits, and [friendlyMessage] above
 * falls back to the identical string for the same case. Kept here as the one place both read from,
 * rather than as two independently-written copies of the same sentence.
 */
fun peerReachedTimeoutMessage(host: String): String =
    "Reached $host and pushed, but lost the connection before the pull " +
        "confirmed it. Your data may already be on the peer."
