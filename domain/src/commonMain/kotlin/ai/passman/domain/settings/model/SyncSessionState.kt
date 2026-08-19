package ai.passman.domain.settings.model

import ai.passman.domain.exception.Failure

/**
 * Lifecycle of a single Sync Mode session. Emitted by the sync use cases as a Flow so the
 * UI can render banner countdowns, cancel buttons, and snackbars for terminal states.
 *
 * Sequence on a happy path:
 *   Idle -> AwaitingPeer(0) -> AwaitingPeer(3) -> ... -> Syncing -> Success
 *
 * Terminal states (Success, Error) are followed by flow completion; on completion the
 * use case stops the local receive server.
 *
 * The [Error.failure] field is typed as [Failure] (not [TransferFailure]) because
 * `TransferFailure` is a marker sealed class whose data variants actually extend
 * `Failure.FeatureFailure` directly - see `TransferFailure.kt`.
 */
sealed class SyncSessionState {
    data object Idle : SyncSessionState()
    data class AwaitingPeer(val host: String, val elapsedSeconds: Int) : SyncSessionState()
    data class Syncing(val host: String) : SyncSessionState()
    data class Success(val host: String) : SyncSessionState()
    data class Error(val failure: Failure, val message: String) : SyncSessionState()
}
