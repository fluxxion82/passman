package ai.passman.viewmodel.sync

import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.settings.model.SyncLogEntry

/**
 * Display text for one sync activity log row. Both functions have an `else` branch rather than an
 * exhaustive `when` over [SyncLogEntry.OUTCOME_SUCCESS]-style constants, because [SyncLogEntry]
 * pins `outcome` and `artifact` as plain strings precisely so an unrecognised value renders here
 * instead of throwing during decode — see [SyncLogEntry]'s KDoc.
 */
fun syncOutcomeLabel(outcome: String): String = when (outcome) {
    SyncLogEntry.OUTCOME_SUCCESS -> "Synced"
    SyncLogEntry.OUTCOME_FAILED -> "Failed"
    SyncLogEntry.OUTCOME_CANCELLED -> "Cancelled"
    else -> "Unknown"
}

fun syncArtifactLabel(artifact: String): String = when (artifact) {
    SyncOps.PASSWORDS -> "Passwords"
    SyncOps.PGP -> "PGP keys"
    SyncOps.KEYSTORE -> "Keystore"
    else -> "Unknown"
}
