@file:OptIn(ExperimentalCoroutinesApi::class)

package ai.passman.domain.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.domain.settings.repository.TransferRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest

/**
 * Characterization tests for [runSyncSession], the bilateral Sync Mode state machine.
 *
 * Every test drives the session with a clock backed by the coroutine test scheduler, so the
 * 3s retry ticks, the elapsed-seconds counter and the 60s deadline all agree with virtual time
 * and the whole 60s window costs no wall time.
 */
class SyncSessionTest {

    // region: test cases

    /**
     * The pairing gate is purely "is this host in the trusted-device table?" - `verifyTrustedFingerprint`
     * no longer compares fingerprints at all (mTLS SPKI pinning binds the channel instead), so there is
     * no fingerprint-mismatch branch left to characterize here.
     */
    @Test
    fun `unpaired host is refused before any push or server start`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(
            transfer = transfer,
            trusted = FakeTrustedDevices(device = null),
            push = push,
            pull = pull,
        ).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.Error(
                    TransferFailure.GeneralTransferFailure,
                    "host not paired: $HOST",
                ),
            ),
            states,
        )
        assertEquals(0, push.calls, "push must not run for an unpaired host")
        assertEquals(0, pull.calls, "pull must not run for an unpaired host")
        assertEquals(0, transfer.startCount, "server must not start for an unpaired host")
        assertEquals(1, transfer.stopCount, "onCompletion must still tear the server down")
        assertEquals(0L, testScheduler.currentTime, "a refusal must not consume any of the window")
    }

    @Test
    fun `first-try success runs push then pull then holds for handshake`() = runTest {
        val transfer = FakeTransferRepository()
        // Production resets peerHandshakeComplete to false inside startTransferServer, so the session
        // always begins with a false flag and the peer flips it mid-session. Model that by completing
        // the handshake from inside the push attempt, i.e. during Phase A and before Success.
        val push = Script("push", Outcome.Success(Unit), onCall = {
            assertEquals(1, transfer.startCount, "the peer can only handshake once our server is up")
            transfer.handshake.value = true
        })
        val pull = Script("pull", Outcome.Success(Unit))

        assertFalse(transfer.peerHandshakeComplete.value, "a fresh session starts with no peer handshake")

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
        )
        assertEquals(1, push.calls)
        assertEquals(1, pull.calls)
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
        assertEquals(
            0L,
            testScheduler.currentTime,
            "a handshake that completed during Phase A must release Phase B without burning the deadline",
        )
    }

    @Test
    fun `peer-unreachable retries every three seconds and reports elapsed`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script(
            "push",
            unreachable(),
            unreachable(),
            Outcome.Success(Unit),
            onCall = { call -> if (call == 2) transfer.handshake.value = true },
        )
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 3),
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 6),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
        )
        assertEquals(3, push.calls, "two retries plus the successful attempt")
        assertEquals(1, pull.calls)
        assertEquals(6_000L, testScheduler.currentTime, "two retry intervals of 3s each")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    @Test
    fun `non-retryable push error stops immediately`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Error("no public key", TransferFailure.PublicKeyFetchFailure))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Error(TransferFailure.PublicKeyFetchFailure, "no public key"),
            ),
            states,
        )
        assertEquals(1, push.calls, "a non-retryable failure must not be retried")
        assertEquals(0, pull.calls)
        assertEquals(0L, testScheduler.currentTime, "no retry delay may be consumed")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    @Test
    fun `pull failure after successful push emits error not success`() = runTest {
        val transfer = FakeTransferRepository()
        val trusted = FakeTrustedDevices(PAIRED_DEVICE)
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Error("pull blew up", TransferFailure.GeneralTransferFailure))

        val states = session(transfer, trusted = trusted, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Error(TransferFailure.GeneralTransferFailure, "pull blew up"),
            ),
            states,
        )
        assertTrue(
            states.none { it is SyncSessionState.Success },
            "a failed pull must never report success",
        )
        assertEquals(1, push.calls)
        assertEquals(1, pull.calls)
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
        assertNull(
            trusted.lastSyncStamp,
            "a failed pull after a successful push must never stamp the device",
        )
    }

    /**
     * Asymmetry worth pinning: PeerUnreachable is the *retryable* failure on the push side, but the
     * pull side has no retry branch at all - any pull error, PeerUnreachable included, is terminal
     * and surfaces verbatim rather than falling back into the 3s retry loop.
     */
    @Test
    fun `peer-unreachable pull failure is terminal and is never retried`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", unreachable())

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Error(TransferFailure.PeerUnreachable(HOST), "peer is down"),
            ),
            states,
        )
        assertEquals(1, push.calls, "a terminal pull must not re-enter the push retry loop")
        assertEquals(1, pull.calls, "the pull itself must not be retried either")
        assertEquals(0L, testScheduler.currentTime, "no retry delay may be consumed on the pull side")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    @Test
    fun `timeout emits PeerSyncTimeout after sixty seconds`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", unreachable(), repeatLast = true)
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        val expected = buildList {
            add(SyncSessionState.Idle)
            add(SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0))
            for (second in 3..60 step 3) {
                add(SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = second))
            }
            add(SyncSessionState.Error(TransferFailure.PeerSyncTimeout(HOST), "peer is down"))
        }
        assertEquals(expected, states)

        val terminal = assertIs<SyncSessionState.Error>(states.last())
        assertIs<TransferFailure.PeerSyncTimeout>(terminal.failure)
        assertEquals(20, push.calls, "one push per 3s tick across the 60s window")
        assertEquals(0, pull.calls)
        assertEquals(60_000L, testScheduler.currentTime, "the session must run exactly to the deadline")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    /**
     * A slow push attempt can leave the unconditional 3s retry delay straddling the deadline: the
     * attempt fails at t=58s, the delay lands at t=61s, and the elapsed counter would read 61. The
     * loop still emits that tick before re-testing its condition, so `coerceAtMost(SYNC_TIMEOUT_SECONDS)`
     * is the only thing keeping the UI countdown from overshooting 60.
     */
    @Test
    fun `a retry delay crossing the deadline clamps the final tick and then times out`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script(
            "push",
            unreachable(),
            unreachable(),
            unreachable(),
            // Third attempt hangs until t=58s, so its retry delay expires at t=61s - past the deadline.
            onCall = { call -> if (call == 2) delay(52_000) },
        )
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 3),
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 6),
                // Raw elapsed here is 61s; the clamp pins the countdown to the advertised 60s window.
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 60),
                SyncSessionState.Error(TransferFailure.PeerSyncTimeout(HOST), "peer is down"),
            ),
            states,
        )
        assertEquals(3, push.calls, "the loop must not attempt another push once the deadline has passed")
        assertEquals(0, pull.calls)
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
        assertEquals(
            61_000L,
            testScheduler.currentTime,
            "the final retry delay is unconditional, so the session overruns the deadline by 1s",
        )
    }

    @Test
    fun `a throwing startTransferServer propagates and still stops the server`() = runTest {
        val transfer = FakeTransferRepository(
            startFailure = IllegalStateException("transfer server refused to bind"),
        )
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = mutableListOf<SyncSessionState>()
        val thrown = assertFailsWith<IllegalStateException> {
            session(transfer, push = push, pull = pull).toList(states)
        }

        assertEquals(
            "transfer server refused to bind",
            thrown.message,
            "the failure must reach the collector intact",
        )
        assertEquals(
            listOf<SyncSessionState>(SyncSessionState.Idle),
            states,
            "a failed server start must not emit AwaitingPeer",
        )
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount, "onCompletion must tear down exactly once even when start threw")
        assertEquals(0, push.calls, "no push may run without a receive server")
        assertEquals(0, pull.calls)
    }

    @Test
    fun `cancellation during await still stops the server`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", unreachable(), repeatLast = true)
        val pull = Script("pull", Outcome.Success(Unit))

        val states = mutableListOf<SyncSessionState>()
        val job = launch { session(transfer, push = push, pull = pull).toList(states) }

        testScheduler.advanceTimeBy(4_000)
        testScheduler.runCurrent()
        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 3),
            ),
            states,
        )
        assertEquals(1, transfer.startCount)
        assertEquals(0, transfer.stopCount, "server stays up while the session is still awaiting")

        job.cancelAndJoin()

        assertEquals(1, transfer.stopCount, "cancellation must still tear the server down exactly once")
        assertEquals(0, pull.calls)
    }

    @Test
    fun `phase B releases when handshake completes`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = mutableListOf<SyncSessionState>()
        val job = launch { session(transfer, push = push, pull = pull).toList(states) }

        testScheduler.runCurrent()
        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
        )
        assertEquals(1, push.calls)
        assertEquals(1, pull.calls)
        assertEquals(1, transfer.startCount)
        assertFalse(job.isCompleted, "phase B must hold the server open for the slower peer")

        testScheduler.advanceTimeBy(10_000)
        testScheduler.runCurrent()
        assertFalse(job.isCompleted, "still holding while the peer has not handshaked")
        assertEquals(0, transfer.stopCount)

        transfer.handshake.value = true
        testScheduler.runCurrent()

        assertTrue(job.isCompleted, "a completed handshake must release the hold early")
        assertEquals(10_000L, testScheduler.currentTime, "released well before the 60s deadline")
        assertEquals(1, transfer.stopCount)
        assertEquals(1, push.calls, "phase B must not re-drive the transfer")
        assertEquals(1, pull.calls, "phase B must not re-drive the transfer")
        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
            "phase B emits nothing of its own",
        )
    }

    @Test
    fun `phase B falls back to the deadline when handshake never completes`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = mutableListOf<SyncSessionState>()
        val job = launch { session(transfer, push = push, pull = pull).toList(states) }

        testScheduler.runCurrent()
        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
        )
        assertEquals(1, transfer.startCount)

        testScheduler.advanceTimeBy(59_999)
        testScheduler.runCurrent()
        assertFalse(job.isCompleted, "the hold must last until the 60s deadline")
        assertEquals(0, transfer.stopCount)

        testScheduler.advanceUntilIdle()

        assertTrue(job.isCompleted)
        assertEquals(60_000L, testScheduler.currentTime, "the hold ends exactly at the deadline")
        assertEquals(1, transfer.stopCount)
        assertEquals(1, push.calls, "a timed-out hold must not re-drive the transfer")
        assertEquals(1, pull.calls, "a timed-out hold must not re-drive the transfer")
        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
            "a timed-out hold is silent - Success stays the terminal state",
        )
    }

    @Test
    fun `successful session stamps the paired device with host and virtual sync time`() = runTest {
        val transfer = FakeTransferRepository()
        val trusted = FakeTrustedDevices(PAIRED_DEVICE)
        val push = Script(
            "push",
            unreachable(),
            unreachable(),
            Outcome.Success(Unit),
            onCall = { call -> if (call == 2) transfer.handshake.value = true },
        )
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, trusted = trusted, push = push, pull = pull).toList()

        assertIs<SyncSessionState.Success>(states.last())
        assertEquals(
            Triple(PAIRED_DEVICE.name, HOST, 6_000L),
            trusted.lastSyncStamp,
            "success after two 3s retries must stamp the device with the host and the virtual clock reading",
        )
    }

    @Test
    fun `failed session leaves the last-sync stamp untouched`() = runTest {
        val transfer = FakeTransferRepository()
        val trusted = FakeTrustedDevices(device = null)
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, trusted = trusted, push = push, pull = pull).toList()

        assertIs<SyncSessionState.Error>(states.last())
        assertNull(trusted.lastSyncStamp, "a refused session must never stamp a device")
    }

    // endregion

    // region: harness

    private fun TestScope.session(
        transfer: FakeTransferRepository,
        trusted: TrustedDevicesRepository = FakeTrustedDevices(PAIRED_DEVICE),
        push: Script,
        pull: Script,
    ): Flow<SyncSessionState> = runSyncSession(
        host = HOST,
        trustedDevices = trusted,
        fingerprintService = FakeFingerprintService,
        transferRepository = transfer,
        push = push::invoke,
        pull = pull::invoke,
        clock = SchedulerClock(testScheduler),
    )

    private fun unreachable() =
        Outcome.Error("peer is down", TransferFailure.PeerUnreachable(HOST))

    private companion object {
        const val HOST = "192.168.1.42"
        val PAIRED_DEVICE = TrustedDevice(
            name = "laptop",
            fingerprint = "AA:BB:CC",
            lastHost = HOST,
        )
    }

    // endregion
}

/** Clock whose readings are the coroutine test scheduler's virtual time. */
private class SchedulerClock(private val scheduler: TestCoroutineScheduler) : Clock {
    override fun now(): Instant = Instant.fromEpochMilliseconds(scheduler.currentTime)
}

/**
 * Scripted push/pull outcomes.
 *
 * Running off the end of the script is an error by default, so a test can never silently absorb an
 * extra attempt the session was not supposed to make. Set [repeatLast] only where the session is
 * genuinely expected to retry an unbounded number of times (timeout / cancellation windows).
 *
 * [onCall] runs before the outcome is returned and receives the zero-based call index, which lets a
 * test mutate the world mid-attempt (flip a handshake flag) or make an attempt consume virtual time.
 */
private class Script(
    private val name: String,
    vararg outcomes: Outcome<Unit>,
    private val repeatLast: Boolean = false,
    private val onCall: suspend (call: Int) -> Unit = {},
) {
    private val scripted = outcomes.toList()

    var calls: Int = 0
        private set

    suspend fun invoke(): Outcome<Unit> {
        val index = calls
        if (index > scripted.lastIndex && !repeatLast) {
            throw AssertionError(
                "'$name' script exhausted: ${scripted.size} outcome(s) scripted, " +
                    "but call #${index + 1} was requested",
            )
        }
        calls++
        onCall(index)
        return scripted[index.coerceAtMost(scripted.lastIndex)]
    }
}

private class FakeTransferRepository(private val startFailure: Throwable? = null) : TransferRepository {
    var startCount: Int = 0
        private set
    var stopCount: Int = 0
        private set

    /** Mirrors production: the flag is false until an inbound push *and* an inbound sync-pull land. */
    val handshake = MutableStateFlow(false)
    override val peerHandshakeComplete: StateFlow<Boolean> get() = handshake

    override suspend fun startTransferServer() {
        startCount++
        startFailure?.let { throw it }
    }

    override suspend fun stopTransferServer() {
        stopCount++
    }

    override suspend fun isTransferServerRunning(): Boolean = startCount > stopCount
    override suspend fun startPairingServer() = Unit
    override suspend fun stopPairingServer() = Unit
    override suspend fun getIpAddress(): String = "127.0.0.1"
    override suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit> =
        Outcome.Success(Unit)

}

private class FakeTrustedDevices(private val device: TrustedDevice?) : TrustedDevicesRepository {
    /** (name, host, timestampMs) of the last [updateLastSync] call, or null if never stamped. */
    var lastSyncStamp: Triple<String, String, Long>? = null
        private set

    override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
    override suspend fun getAll(): List<TrustedDevice> = listOfNotNull(device)
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
    override suspend fun remove(name: String) = Unit
    override suspend fun getByHost(host: String): TrustedDevice? = device
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) {
        lastSyncStamp = Triple(name, host, timestampMs)
    }
    override suspend fun updateHost(name: String, host: String) = Unit
    override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
    override suspend fun markSignedHybridPairingsForReverification() = Unit
}

/**
 * The session is documented as never touching the fingerprint service (mTLS SPKI pinning binds the
 * channel instead), so every member is a loud failure rather than a silent stub.
 */
private object FakeFingerprintService : FingerprintService {
    override fun digest(bytes: ByteArray): ByteArray = unused()
    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = unused()
    override fun randomBytes(count: Int): ByteArray = unused()
    override fun fingerprintOf(publicKeyBytes: ByteArray): String = unused()
    override suspend fun getOwnFingerprint(): Outcome<String> = unused()
    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = unused()
    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = unused()
    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
        unused()

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> = unused()

    private fun unused(): Nothing =
        error("the sync session must not touch FingerprintService")
}
