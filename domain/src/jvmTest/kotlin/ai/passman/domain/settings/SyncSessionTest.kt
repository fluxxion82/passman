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
        assertEquals(
            0,
            transfer.stopCount,
            "onCompletion must not release a lease this session never took - the server is refcounted, " +
                "and a stop here with no matching start would steal a lease from a sibling artifact " +
                "session (pgp/keystore) still using the shared server",
        )
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
     * Obligation 1 (rewrite) / obligation 4 (new): this used to pin the opposite - a PeerUnreachable
     * pull failure was terminal on the first attempt, with `pull.calls == 1` and
     * `currentTime == 0L`. That was backwards: a pull only runs after a *successful* push to the
     * same host and port, which proves the peer's server was accepting milliseconds earlier, so a
     * ConnectException on the pull means the peer's server went down in the teardown window between
     * our push and our pull - not that it never came up. That is recoverable exactly the way a
     * push-side PeerUnreachable is, so it now retries on the same 3s cadence out of the same shared
     * deadline, and eventually reaches Success once the peer's server is back.
     *
     * Also pins obligation 9 (what the pull retries emit): no AwaitingPeer state reappears between
     * Syncing and Success. Re-emitting AwaitingPeer - the "waiting to even start" state - after
     * Syncing would visibly regress the UI backwards, so the pull retries are silent.
     */
    @Test
    fun `peer-unreachable pull failure retries and succeeds on a later attempt`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit), onCall = { transfer.handshake.value = true })
        val pull = Script("pull", unreachable(), unreachable(), Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Success(HOST),
            ),
            states,
            "no AwaitingPeer must reappear while the pull retries - Syncing stays the last visible state",
        )
        assertEquals(
            1,
            push.calls,
            "a retried pull must not re-push - re-running the push would re-stage a temp file on the " +
                "peer and raise a spurious reconcile conflict for data that already arrived once",
        )
        assertEquals(3, pull.calls, "two retries plus the successful attempt")
        assertEquals(6_000L, testScheduler.currentTime, "two pull retry intervals of 3s each")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    /**
     * Obligation 6: only [TransferFailure.PeerUnreachable] retries on the pull side. Everything
     * else - a decrypt failure, an unpaired host, a refused handshake - is an answer, not an
     * absence, and stays terminal on the very first attempt exactly like a non-retryable push
     * error already does.
     */
    @Test
    fun `non-peer-unreachable pull failure stays terminal on the first attempt`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Error("no hybrid key", TransferFailure.PublicKeyFetchFailure))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Error(TransferFailure.PublicKeyFetchFailure, "no hybrid key"),
            ),
            states,
        )
        assertEquals(1, push.calls)
        assertEquals(1, pull.calls, "a non-PeerUnreachable pull failure must not be retried")
        assertEquals(0L, testScheduler.currentTime, "no retry delay may be consumed")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    /**
     * Obligation 7: a PeerUnreachable pull retries, but the moment a later attempt comes back with
     * a *different*, non-retryable failure, the loop must stop immediately rather than keep
     * retrying (which would misreport the real failure as more unreachability) or paper over it as
     * another PeerUnreachable tick.
     */
    @Test
    fun `a peer-unreachable pull followed by a non-retryable error terminates mid-retry`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script(
            "pull",
            unreachable(),
            unreachable(),
            Outcome.Error("payload did not decrypt", TransferFailure.GeneralTransferFailure),
        )

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Error(TransferFailure.GeneralTransferFailure, "payload did not decrypt"),
            ),
            states,
            "no AwaitingPeer reappears during the retries, and the final error is the real one, not PeerUnreachable",
        )
        assertEquals(1, push.calls, "still must not re-push")
        assertEquals(3, pull.calls, "two retries, then the non-retryable failure that stops the loop")
        assertEquals(6_000L, testScheduler.currentTime, "two pull retry intervals of 3s each before stopping")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
    }

    /**
     * Obligation 8: pull retries spend the *same* 60s budget the push retries would have, not a
     * fresh one of their own - a push that succeeds immediately leaves the full window for the
     * pull to retry in, and it still times out at t=60s, not t=120s.
     *
     * This is also the case the "tell the truth on timeout" fix exists for: the push succeeded, so
     * the peer's server demonstrably came up and our vault may already be sitting on it. Reporting
     * that as `PeerSyncTimeout(reachedPeer = false)` / "did not enter sync mode" would be exactly
     * the false permanent record the sync activity log must not persist - see obligation 14 in
     * `SyncOutcomeRecordingTest` for the log-persistence side of this.
     *
     * Also pins obligation 9 alongside the earlier retry-then-succeed test: nothing but Idle,
     * AwaitingPeer(0) and Syncing precedes the terminal state, however many pull attempts it took.
     */
    @Test
    fun `pull retries share the session deadline and a reached-then-lost timeout tells the truth`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", unreachable(), repeatLast = true)

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 0),
                SyncSessionState.Syncing(HOST),
                SyncSessionState.Error(
                    TransferFailure.PeerSyncTimeout(HOST, reachedPeer = true),
                    "Reached $HOST and pushed, but lost the connection before the pull confirmed it. " +
                        "Your data may already be on the peer.",
                ),
            ),
            states,
        )
        assertEquals(1, push.calls, "the push succeeded once and is never retried once pushSucceeded is true")
        assertEquals(20, pull.calls, "one pull attempt per 3s tick across the full 60s window")
        assertEquals(
            60_000L,
            testScheduler.currentTime,
            "the pull retries spent the whole shared deadline, not a second 60s window of their own",
        )
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
     * Obligation 2 (rewrite): a slow push attempt can leave a naive, unconditional 3s retry delay
     * straddling the deadline - the attempt fails at t=58s, an unclamped delay would land at t=61s,
     * and the elapsed counter would read 61. `retryDelayMs` clamps the sleep itself to whatever
     * remains of the deadline, so the loop can no longer overrun it at all: this scenario now ends
     * *at* the deadline (t=60s) rather than 1s past it, and the old cosmetic
     * `elapsed.coerceAtMost(SYNC_TIMEOUT_SECONDS)` at the emit site is gone because there is nothing
     * left for it to clamp.
     */
    @Test
    fun `a retry delay crossing the deadline clamps the final tick and then times out`() = runTest {
        val transfer = FakeTransferRepository()
        val push = Script(
            "push",
            unreachable(),
            unreachable(),
            unreachable(),
            // Third attempt hangs until t=58s, so an unclamped retry delay would expire at t=61s.
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
                // The clamped delay lands exactly at the deadline, not past it.
                SyncSessionState.AwaitingPeer(HOST, elapsedSeconds = 60),
                SyncSessionState.Error(TransferFailure.PeerSyncTimeout(HOST, reachedPeer = false), "peer is down"),
            ),
            states,
        )
        assertEquals(3, push.calls, "the loop must not attempt another push once the deadline has passed")
        assertEquals(0, pull.calls)
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount)
        assertEquals(
            60_000L,
            testScheduler.currentTime,
            "the clamped retry delay can no longer carry the session past its own deadline",
        )
    }

    /**
     * Obligation 3 (rewrite): this used to pin the opposite - a thrown [IllegalStateException]
     * propagated out of the flow to the collector. That was a real hazard: `runSyncSession` is
     * collected in `viewModelScope.launch { }` with no catch downstream
     * (`PasswordHomeViewModel.startSession`), so an uncaught exception there kills the process
     * rather than showing an error. A failed bind is now caught, reported as
     * [SyncSessionState.Error], and the flow ends normally instead.
     *
     * It must also not release a lease: [FakeTransferRepository.startTransferServer] mirrors
     * production's `FileTransferRepository`, which rolls its own lease back internally before
     * throwing, so this session was never holding one. Calling `stopTransferServer()` anyway - the
     * old, unrefcounted-era assumption that "we tried to start, therefore we must stop" - would
     * release a lease that belongs to whichever sibling artifact session (pgp/keystore) is still
     * using the shared server.
     */
    @Test
    fun `a failing startTransferServer emits Error, releases no lease, and never propagates`() = runTest {
        val transfer = FakeTransferRepository(
            startFailure = IllegalStateException("transfer server refused to bind"),
        )
        val push = Script("push", Outcome.Success(Unit))
        val pull = Script("pull", Outcome.Success(Unit))

        val states = session(transfer, push = push, pull = pull).toList()

        assertEquals(
            listOf(
                SyncSessionState.Idle,
                SyncSessionState.Error(
                    TransferFailure.GeneralTransferFailure,
                    "transfer server refused to bind",
                ),
            ),
            states,
            "a failed server start must surface as a terminal Error, not AwaitingPeer or a thrown exception",
        )
        assertEquals(1, transfer.startCount)
        assertEquals(
            0,
            transfer.stopCount,
            "a failed start already rolled its own lease back internally - stopping again would " +
                "release a lease this session never held, stealing one from a sibling session",
        )
        assertEquals(0, push.calls, "no push may run without a receive server")
        assertEquals(0, pull.calls)
    }

    /**
     * Review finding: `started` is declared outside `flow { }` so `onCompletion` can see it across
     * that lambda boundary, but that makes it a variable of the returned Flow *instance* rather
     * than of one collection - and a cold flow has to behave the same on its second collection as
     * its first (`recordingOutcomes` documents the identical shape for its own `terminalRecorded`
     * flag, in `SyncPasswords.kt`). This collects the very same [Flow] twice: the first collection
     * starts the server and completes normally, and only the second turns unpaired - so if the
     * `.onStart { started = false }` reset were ever removed, the stale `true` left over from the
     * first collection would make `onCompletion` release a lease the second collection never took,
     * stealing one from whichever sibling artifact session (pgp/keystore) is still using the
     * shared server.
     */
    @Test
    fun `a second collection that never starts the server does not release the first's lease`() = runTest {
        val transfer = FakeTransferRepository()
        val trusted = ToggleableTrustedDevices(PAIRED_DEVICE)
        val push = Script("push", Outcome.Success(Unit), onCall = { transfer.handshake.value = true })
        val pull = Script("pull", Outcome.Success(Unit))

        val flow = session(transfer, trusted = trusted, push = push, pull = pull)

        val first = flow.toList()
        assertIs<SyncSessionState.Success>(first.last(), "the first collection must start and finish normally")
        assertEquals(1, transfer.startCount)
        assertEquals(1, transfer.stopCount, "the first collection's own lease must be released")

        // Second collection of the exact same Flow instance - this time verification fails before
        // the server is ever started.
        trusted.paired = false
        val second = flow.toList()

        assertIs<SyncSessionState.Error>(second.last())
        assertEquals(1, transfer.startCount, "a verify failure must never start the server")
        assertEquals(
            1,
            transfer.stopCount,
            "the second collection never started the server, so onCompletion must not release a " +
                "lease it never took - a stale `started` flag left over from the first collection " +
                "would otherwise leak exactly that release",
        )
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

/**
 * Clock whose readings are the coroutine test scheduler's virtual time.
 *
 * Internal rather than file-private because `SyncOutcomeRecordingTest` needs it too: any test that
 * lets a session run to its deadline has to read time from the same virtual clock its `delay`s run
 * on, or the loop spins in real time until the harness times the test out.
 */
internal class SchedulerClock(private val scheduler: TestCoroutineScheduler) : Clock {
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
 * A [TrustedDevicesRepository] whose pairing can be flipped mid-test, for the `started`-reset
 * regression test above: the first collection of a session's Flow needs the host paired, and the
 * second needs it unpaired, on the exact same fake instance backing the exact same Flow.
 */
private class ToggleableTrustedDevices(private val device: TrustedDevice) : TrustedDevicesRepository {
    var paired: Boolean = true

    override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
    override suspend fun getAll(): List<TrustedDevice> = if (paired) listOf(device) else emptyList()
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
    override suspend fun remove(name: String) = Unit
    override suspend fun getByHost(host: String): TrustedDevice? = if (paired) device else null
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
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
