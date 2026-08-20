package ai.passman.domain.settings

import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest

/**
 * [RecordSyncOutcome] is the one seam every sync wrapper calls through, so its jobs — write the row
 * it was handed, and never let a storage failure escape into the sync flow — are pinned here once
 * rather than three times inside `SyncOutcomeRecordingTest`.
 *
 * The device name is now *given* rather than resolved from the host. It used to be looked up with
 * `TrustedDevicesRepository.getByHost`, a first match over an address two pairings can share, so a
 * row could name a device the user never synced with; the session already holds the record it was
 * started with and passes its name straight through.
 */
class RecordSyncOutcomeTest {

    private val fixedClock = object : Clock {
        override fun now(): Instant = Instant.fromEpochMilliseconds(FIXED_TIME_MS)
    }

    @Test
    fun `the given device name is written onto the recorded entry verbatim`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val recordSyncOutcome = RecordSyncOutcome(log, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(
                artifact = "passwords",
                host = HOST,
                deviceName = "laptop",
                outcome = SyncLogEntry.OUTCOME_SUCCESS,
            ),
        )

        assertEquals(
            listOf(
                SyncLogEntry(
                    at = FIXED_TIME_MS,
                    artifact = "passwords",
                    host = HOST,
                    deviceName = "laptop",
                    outcome = SyncLogEntry.OUTCOME_SUCCESS,
                ),
            ),
            log.appended,
        )
    }

    /**
     * Two pairings sharing one address is exactly the case the old by-host resolution got wrong: it
     * answered with whichever record came first, so a row could name the device the user did *not*
     * sync with. Nothing here resolves anything any more — whichever of the two the session was
     * given is the name that lands — and this pins that there is no lookup left to go wrong.
     */
    @Test
    fun `a host shared by two pairings still records the device the session names`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val recordSyncOutcome = RecordSyncOutcome(log, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(
                artifact = "passwords",
                host = HOST,
                deviceName = "laptop-re-paired",
                outcome = SyncLogEntry.OUTCOME_SUCCESS,
            ),
        )

        assertEquals("laptop-re-paired", log.appended.single().deviceName)
    }

    /** Obligation 3: a caller with no device to name still gets its row; [HOST] carries it. */
    @Test
    fun `an empty device name records an empty name and still appends`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val recordSyncOutcome = RecordSyncOutcome(log, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(
                artifact = "pgp-keys",
                host = HOST,
                deviceName = "",
                outcome = SyncLogEntry.OUTCOME_FAILED,
                detail = "Could not reach $HOST. The peer's IP may have changed.",
            ),
        )

        val entry = log.appended.single()
        assertEquals("", entry.deviceName, "a nameless caller must not fail the recording")
        assertEquals("Could not reach $HOST. The peer's IP may have changed.", entry.detail)
    }

    /** Obligation 4 (use-case slice; the flow-level slice lives in `SyncOutcomeRecordingTest`). */
    @Test
    fun `a repository failure is logged and swallowed, never thrown`() = runTest {
        val log = RecordOutcomeTestSyncLog(throwOnAppend = IllegalStateException("disk full"))
        val recordSyncOutcome = RecordSyncOutcome(log, fixedClock)

        // No assertFailsWith here on purpose: the point under test is that nothing escapes.
        recordSyncOutcome(
            RecordSyncOutcome.Params(
                artifact = "keystore",
                host = HOST,
                deviceName = "laptop",
                outcome = SyncLogEntry.OUTCOME_SUCCESS,
            ),
        )
    }

    /**
     * A cancelled caller must not be told its recording was silently dropped-and-handled the way a
     * genuine storage failure is - that would let the sync flow's cancellation appear to complete
     * cleanly through this use case instead of propagating.
     */
    @Test
    fun `cancellation is rethrown rather than swallowed`() = runTest {
        val log = RecordOutcomeTestSyncLog(throwOnAppend = CancellationException("cancelled"))
        val recordSyncOutcome = RecordSyncOutcome(log, fixedClock)

        assertFailsWith<CancellationException> {
            recordSyncOutcome(
                RecordSyncOutcome.Params(
                    artifact = "keystore",
                    host = HOST,
                    deviceName = "laptop",
                    outcome = SyncLogEntry.OUTCOME_SUCCESS,
                ),
            )
        }
    }

    private companion object {
        const val HOST = "192.0.2.5"
        const val FIXED_TIME_MS = 1_700_000_000_000L
    }
}

private class RecordOutcomeTestSyncLog(private val throwOnAppend: Throwable? = null) : SyncLogRepository {
    val appended = mutableListOf<SyncLogEntry>()

    override suspend fun append(entry: SyncLogEntry) {
        throwOnAppend?.let { throw it }
        appended += entry
    }

    override suspend fun recent(): List<SyncLogEntry> = appended.toList()

    override suspend fun clear() {
        appended.clear()
    }
}
