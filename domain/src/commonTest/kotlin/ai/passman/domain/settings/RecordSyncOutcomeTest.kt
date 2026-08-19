package ai.passman.domain.settings

import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.runTest

/**
 * [RecordSyncOutcome] is the one seam every sync wrapper calls through, so its two jobs — resolve
 * a device name from a host, and never let a storage failure escape into the sync flow — are
 * pinned here once rather than three times inside `SyncOutcomeRecordingTest`.
 */
class RecordSyncOutcomeTest {

    private val fixedClock = object : Clock {
        override fun now(): Instant = Instant.fromEpochMilliseconds(FIXED_TIME_MS)
    }

    @Test
    fun `a paired host resolves its device name onto the recorded entry`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val trustedDevices = RecordOutcomeTestTrustedDevices(TrustedDevice(name = "laptop", fingerprint = "fp", lastHost = HOST))
        val recordSyncOutcome = RecordSyncOutcome(log, trustedDevices, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(artifact = "passwords", host = HOST, outcome = SyncLogEntry.OUTCOME_SUCCESS),
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

    /** Obligation 3. */
    @Test
    fun `an unknown host records an empty device name and still appends`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val trustedDevices = RecordOutcomeTestTrustedDevices(device = null)
        val recordSyncOutcome = RecordSyncOutcome(log, trustedDevices, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(
                artifact = "pgp-keys",
                host = HOST,
                outcome = SyncLogEntry.OUTCOME_FAILED,
                detail = "Could not reach $HOST. The peer's IP may have changed.",
            ),
        )

        val entry = log.appended.single()
        assertEquals("", entry.deviceName, "an unpaired/removed host must not fail the recording")
        assertEquals("Could not reach $HOST. The peer's IP may have changed.", entry.detail)
    }

    /** Obligation 4 (use-case slice; the flow-level slice lives in `SyncOutcomeRecordingTest`). */
    @Test
    fun `a repository failure is logged and swallowed, never thrown`() = runTest {
        val log = RecordOutcomeTestSyncLog(throwOnAppend = IllegalStateException("disk full"))
        val trustedDevices = RecordOutcomeTestTrustedDevices(device = null)
        val recordSyncOutcome = RecordSyncOutcome(log, trustedDevices, fixedClock)

        // No assertFailsWith here on purpose: the point under test is that nothing escapes.
        recordSyncOutcome(
            RecordSyncOutcome.Params(artifact = "keystore", host = HOST, outcome = SyncLogEntry.OUTCOME_SUCCESS),
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
        val trustedDevices = RecordOutcomeTestTrustedDevices(device = null)
        val recordSyncOutcome = RecordSyncOutcome(log, trustedDevices, fixedClock)

        assertFailsWith<CancellationException> {
            recordSyncOutcome(
                RecordSyncOutcome.Params(artifact = "keystore", host = HOST, outcome = SyncLogEntry.OUTCOME_SUCCESS),
            )
        }
    }

    /** A lookup failure is exactly as harmless to the sync as an append failure. */
    @Test
    fun `a trusted-device lookup failure is also swallowed`() = runTest {
        val log = RecordOutcomeTestSyncLog()
        val trustedDevices = ThrowingTrustedDevices(IllegalStateException("store unreadable"))
        val recordSyncOutcome = RecordSyncOutcome(log, trustedDevices, fixedClock)

        recordSyncOutcome(
            RecordSyncOutcome.Params(artifact = "passwords", host = HOST, outcome = SyncLogEntry.OUTCOME_SUCCESS),
        )

        assertEquals(emptyList(), log.appended, "a lookup that never completed must not append a half-built entry")
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

private class RecordOutcomeTestTrustedDevices(private val device: TrustedDevice?) : TrustedDevicesRepository {
    override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
    override suspend fun getAll(): List<TrustedDevice> = listOfNotNull(device)
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
    override suspend fun remove(name: String) = Unit
    override suspend fun getByHost(host: String): TrustedDevice? = device
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
    override suspend fun updateHost(name: String, host: String) = Unit
    override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
    override suspend fun markSignedHybridPairingsForReverification() = Unit
}

private class ThrowingTrustedDevices(private val error: Throwable) : TrustedDevicesRepository {
    override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
    override suspend fun getAll(): List<TrustedDevice> = throw error
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
    override suspend fun remove(name: String) = Unit
    override suspend fun getByHost(host: String): TrustedDevice? = throw error
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
    override suspend fun updateHost(name: String, host: String) = Unit
    override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
    override suspend fun markSignedHybridPairingsForReverification() = Unit
}
