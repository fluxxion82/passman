package ai.passman.viewmodel.sync

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.friendlyMessage

fun Outcome.Error.toSyncError(): SyncState.Error = SyncState.Error(
    message = friendlyMessage(cause, fallback = message),
    noSavedAddress = cause is TransferFailure.NoSavedAddress,
)
