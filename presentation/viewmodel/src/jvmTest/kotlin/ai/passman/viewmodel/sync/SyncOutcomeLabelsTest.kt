package ai.passman.viewmodel.sync

import ai.passman.domain.settings.model.SyncLogEntry
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Obligation 7 (render half; the decode half — an unrecognised outcome surviving a JSON round
 * trip — is pinned in `SyncLogEntryTest`). [SyncLogEntry.outcome] and `.artifact` are plain
 * strings precisely so a value this build does not recognise (an older row, or a newer one
 * written by a build ahead of this one) renders through the `else` branch instead of crashing the
 * screen.
 */
class SyncOutcomeLabelsTest {

    @Test
    fun `known outcomes get their own label`() {
        assertEquals("Synced", syncOutcomeLabel(SyncLogEntry.OUTCOME_SUCCESS))
        assertEquals("Failed", syncOutcomeLabel(SyncLogEntry.OUTCOME_FAILED))
        assertEquals("Cancelled", syncOutcomeLabel(SyncLogEntry.OUTCOME_CANCELLED))
    }

    @Test
    fun `an unrecognised outcome renders via the else branch instead of throwing`() {
        assertEquals("Unknown", syncOutcomeLabel("partial-retry"))
    }

    @Test
    fun `known artifacts get their own label`() {
        assertEquals("Passwords", syncArtifactLabel("passwords"))
        assertEquals("PGP keys", syncArtifactLabel("pgp-keys"))
        assertEquals("Keystore", syncArtifactLabel("keystore"))
    }

    @Test
    fun `an unrecognised artifact renders via the else branch instead of throwing`() {
        assertEquals("Unknown", syncArtifactLabel("totp-seeds"))
    }
}
