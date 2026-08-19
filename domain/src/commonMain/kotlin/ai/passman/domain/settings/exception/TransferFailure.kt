package ai.passman.domain.settings.exception

import ai.passman.domain.exception.Failure

sealed class TransferFailure {
    data object PublicKeyFetchFailure: Failure.FeatureFailure()
    data object GeneralTransferFailure: Failure.FeatureFailure()
    data class PeerUnreachable(val host: String): Failure.FeatureFailure()
    data object NoSavedAddress: Failure.FeatureFailure()
    data class FingerprintMismatch(
        val host: String,
        val deviceName: String,
        val expected: String,
        val actual: String,
    ): Failure.FeatureFailure()
    /**
     * The shared 60s window ran out before the session finished. [reachedPeer] distinguishes two
     * situations a flat "timed out" would conflate: `false` means we never even landed a push on
     * [host] (every attempt was `PeerUnreachable`); `true` means the push succeeded — proof the
     * peer's server was up and our vault may already be sitting on it — and it was the *pull*
     * retries that ran out the clock instead. Defaults to `false` so existing "never reached"
     * call sites don't have to name the parameter. See `SyncPasswords.runSyncSession` and
     * `friendlyMessage`, both of which branch on this rather than always reporting "did not enter
     * sync mode" — that sentence is false in the `true` case and is also what the sync activity
     * log persists as `detail`, so getting it wrong there makes it a permanent false record.
     */
    data class PeerSyncTimeout(val host: String, val reachedPeer: Boolean = false): Failure.FeatureFailure()
    data object SyncCancelled: Failure.FeatureFailure()
}
