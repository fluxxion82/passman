package ai.passman.domain.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.connectivity.verifyTrustedFingerprint
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.domain.settings.repository.TransferRepository
import kotlin.time.Clock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class SyncPasswords(
    private val passwordRepository: PasswordRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val passwordEventPersistence: PasswordEventPersistence,
    private val recordSyncOutcome: RecordSyncOutcome,
    /**
     * Injectable only so wrapper-level tests can drive the session on the same virtual clock their
     * `delay`s run on. Production always uses the system clock.
     *
     * Without this the wrapper reads real time while `runTest` makes every `delay` instant, so the
     * 60s deadline never arrives in step with the retry loop and a test that exercises the timeout
     * spins for a full minute of wall time before the harness kills it.
     */
    internal val clock: Clock = Clock.System,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        clock = clock,
        push = { passwordRepository.pushPasswordDatabase(host) },
        pull = { passwordRepository.pullPasswordDatabase(host) },
    ).recordingOutcomes(SyncOps.PASSWORDS, host, recordSyncOutcome) {
        passwordEventPersistence.update(PasswordEvent.Updated)
    }
}

class SyncPgpKeys(
    private val pgpRepository: ai.passman.domain.pgp.repository.PgpRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val pgpEventPersistence: PgpEventPersistence,
    private val recordSyncOutcome: RecordSyncOutcome,
    /**
     * Injectable only so wrapper-level tests can drive the session on the same virtual clock their
     * `delay`s run on. Production always uses the system clock.
     *
     * Without this the wrapper reads real time while `runTest` makes every `delay` instant, so the
     * 60s deadline never arrives in step with the retry loop and a test that exercises the timeout
     * spins for a full minute of wall time before the harness kills it.
     */
    internal val clock: Clock = Clock.System,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        clock = clock,
        push = { pgpRepository.pushPgpKeys(host) },
        pull = { pgpRepository.pullPgpKeys(host) },
    ).recordingOutcomes(SyncOps.PGP, host, recordSyncOutcome) {
        pgpEventPersistence.update(PgpEvent.KeyModified)
    }
}

class SyncKeystores(
    private val keystoreRepository: ai.passman.domain.keystore.repository.KeystoreRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val keystoreEventPersistence: KeystoreEventPersistence,
    private val recordSyncOutcome: RecordSyncOutcome,
    /**
     * Injectable only so wrapper-level tests can drive the session on the same virtual clock their
     * `delay`s run on. Production always uses the system clock.
     *
     * Without this the wrapper reads real time while `runTest` makes every `delay` instant, so the
     * 60s deadline never arrives in step with the retry loop and a test that exercises the timeout
     * spins for a full minute of wall time before the harness kills it.
     */
    internal val clock: Clock = Clock.System,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        clock = clock,
        push = { keystoreRepository.pushKeystores(host) },
        pull = { keystoreRepository.pullKeystores(host) },
    ).recordingOutcomes(SyncOps.KEYSTORE, host, recordSyncOutcome) {
        keystoreEventPersistence.update(KeystoreEvent.Updated)
    }
}

/**
 * Wraps [runSyncSession]'s flow with sync-log recording, shared by all three wrappers above.
 *
 * [onEach] alone is not the real shape of cancellation: it only fires on an *emission*, but a real
 * cancellation — `syncJob?.cancel()` on the collecting coroutine, the way every Home ViewModel
 * stops a sync — kills the collector without [runSyncSession] ever emitting a terminal
 * [SyncSessionState]. A user who cancels mid-`pull`, after `push` already landed their vault on
 * the peer, would otherwise get a log claiming the session never happened — the exact lie this
 * feature exists to prevent. [onCompletion] sees every ending [runSyncSession] can have,
 * cancellation included, so the real-cancellation record belongs there. It only writes one while
 * [terminalRecorded] is still false, so a cancellation landing after a terminal state was already
 * recorded (say, during [runSyncSession]'s post-success handshake hold) does not also file a
 * contradicting cancelled row on top of the success that already happened; on an ordinary
 * (non-cancelled) completion [cause] is null and nothing further is written at all.
 *
 * Both recordings run under [NonCancellable]: [onEach]'s, because otherwise a cancellation racing
 * between the terminal emission and the append could drop the append entirely — the same gap
 * [onCompletion] exists to close, just narrower — and [onCompletion]'s, because it runs exactly
 * while the collecting coroutine is already cancelled, and a suspend call made without
 * [NonCancellable] there would itself be cancelled before it ever reached the store.
 */
private fun Flow<SyncSessionState>.recordingOutcomes(
    artifact: String,
    host: String,
    recordSyncOutcome: RecordSyncOutcome,
    onSuccess: suspend () -> Unit,
): Flow<SyncSessionState> {
    var terminalRecorded = false
    return onStart {
        // Reset per collection, not per flow instance. Every caller builds a fresh flow by calling
        // the wrapper's invoke(host) again, so today this never differs — but a cold flow has to
        // behave the same on its second collection as its first, and without this the captured flag
        // would still read true from the previous run and silently skip the cancellation record.
        terminalRecorded = false
    }.onEach { state ->
        if (state is SyncSessionState.Success) {
            onSuccess()
        }
        if (state is SyncSessionState.Success || state is SyncSessionState.Error) {
            withContext(NonCancellable) { recordSyncOutcome.recordTerminalState(artifact, host, state) }
            terminalRecorded = true
        }
    }.onCompletion { cause ->
        if (cause is CancellationException && !terminalRecorded) {
            withContext(NonCancellable) {
                recordSyncOutcome(
                    RecordSyncOutcome.Params(artifact = artifact, host = host, outcome = SyncLogEntry.OUTCOME_CANCELLED),
                )
            }
        }
    }
}

/**
 * Records one session's terminal state to the sync activity log, called only for a terminal state
 * ([SyncSessionState.Success], [SyncSessionState.Error]) by [recordingOutcomes] above.
 *
 * Lives here rather than inside [runSyncSession] because [runSyncSession] is shared by all three
 * artifacts and has no way to know which one it is running for — each wrapper knows its own
 * [artifact] statically, which is exactly why recording is wired in at this seam. The non-terminal
 * branch below ([SyncSessionState.Idle], [SyncSessionState.AwaitingPeer],
 * [SyncSessionState.Syncing]) is dead in practice — [recordingOutcomes] never calls this function
 * for one — and stays only as an exhaustiveness backstop against a future [SyncSessionState] case
 * this `when` has not been taught about; a log that recorded every tick of a session would bury
 * the outcome the user actually wants under progress noise nobody asked to see later.
 *
 * [SyncSessionState.Error] with a [TransferFailure.SyncCancelled] cause is recorded as
 * [SyncLogEntry.OUTCOME_CANCELLED], not [SyncLogEntry.OUTCOME_FAILED] — the user stopping a sync
 * on purpose is a different outcome from the sync failing on its own, and the log should say so.
 * Nothing in production constructs [TransferFailure.SyncCancelled] today: real cancellation kills
 * the collecting coroutine before [runSyncSession] ever emits a [SyncSessionState.Error], which is
 * exactly what [recordingOutcomes]'s `onCompletion` handles instead. This mapping is kept for a
 * future in-band cancellation that reports itself as an [Outcome.Error], not because it currently
 * fires. [detail] is [friendlyMessage] applied to the same failure and message the live snackbar
 * showed, so a logged failure reads the same after the fact as it did at the time.
 */
private suspend fun RecordSyncOutcome.recordTerminalState(
    artifact: String,
    host: String,
    state: SyncSessionState,
) {
    when (state) {
        is SyncSessionState.Success -> invoke(
            RecordSyncOutcome.Params(artifact = artifact, host = host, outcome = SyncLogEntry.OUTCOME_SUCCESS),
        )

        is SyncSessionState.Error -> invoke(
            RecordSyncOutcome.Params(
                artifact = artifact,
                host = host,
                outcome = if (state.failure is TransferFailure.SyncCancelled) {
                    SyncLogEntry.OUTCOME_CANCELLED
                } else {
                    SyncLogEntry.OUTCOME_FAILED
                },
                detail = friendlyMessage(state.failure, state.message),
            ),
        )

        SyncSessionState.Idle,
        is SyncSessionState.AwaitingPeer,
        is SyncSessionState.Syncing,
        -> Unit
    }
}

private const val SYNC_TIMEOUT_SECONDS = 60

// Shared by both retry loops below (push and pull): a pull failing with PeerUnreachable gets the
// same cadence the push already had, out of the same 60s budget rather than a second one of its
// own - see runSyncSession's KDoc for why a second deadline is off the table.
private const val RETRY_INTERVAL_MS = 3_000L

/**
 * How long to sleep before the next retry, clamped to whatever remains of [deadlineMs].
 *
 * `delay(RETRY_INTERVAL_MS)` on its own is unconditional and the deadline is only re-tested at the
 * top of the retry loop, so an attempt that fails close to the deadline could otherwise sleep past
 * it - the session would overrun its advertised 60s window by up to [RETRY_INTERVAL_MS] before
 * timing out. Clamping here means the loop's elapsed-time reading can never exceed the deadline
 * either, which is what let the old `elapsed.coerceAtMost(SYNC_TIMEOUT_SECONDS)` cosmetic clamp at
 * the call site go away - there is nothing left for it to clamp.
 */
private fun retryDelayMs(clock: Clock, deadlineMs: Long): Long =
    (deadlineMs - clock.now().toEpochMilliseconds()).coerceIn(0, RETRY_INTERVAL_MS)

/**
 * Drives a single bilateral Sync Mode session as a Flow. The caller cancels by cancelling
 * the collecting coroutine; `onCompletion` then tears down the receive server regardless of
 * how the flow ended (success, error, cancellation) - but only if this session actually holds a
 * lease to release (see step 2 below).
 *
 * Lifecycle:
 *  1. Verify peer fingerprint against any paired TrustedDevice. Mismatch -> emit Error and stop.
 *     No lease has been taken yet, so `onCompletion` must not release one either.
 *  2. Start receive server. [TransferRepository.startTransferServer] is refcounted and now throws
 *     on a failed bind instead of swallowing it (see its KDoc); a lease is held if and only if
 *     that call returns normally. A thrown failure is caught here, reported as
 *     [SyncSessionState.Error], and never rethrown - this flow is collected in
 *     `viewModelScope.launch { }` with no catch downstream (`PasswordHomeViewModel.startSession`),
 *     so letting it propagate would kill the process rather than show an error. The failed call
 *     already rolled its own lease back internally before throwing, so this session was never
 *     holding one to release - `started` records that fact for `onCompletion`.
 *  3. Phase A: push to peer every 3s for up to 60s. Emit AwaitingPeer ticks for the countdown.
 *     A push is attempted at most once per session; the moment one succeeds, Phase A never runs
 *     again even if the pull that follows it has to retry (see Phase A/B below).
 *  4. Phase A/B: once a push has succeeded, pull from peer. A pull failing with
 *     [TransferFailure.PeerUnreachable] retries on the same 3s cadence and the same 60s budget as
 *     Phase A, silently (no new state - see the pull-retry branch below for why). Every other pull
 *     failure is terminal on the spot: a decrypt failure, an unpaired host or a refused handshake
 *     is an answer, not an absence, and retrying it would just repeat it until the deadline. A
 *     retried pull only ever calls `pull()` again, never `push()` - re-running the push would
 *     re-enter the peer's `processUploadedFile`, stage a second temp file and flip on a spurious
 *     conflict that sends the peer to its Reconcile screen for data that already arrived once.
 *  5. On success -> emit Success and stamp the trusted device's last-synced time.
 *  6. If the shared deadline runs out before success, the terminal message has to say which of two
 *     different things happened - see the timeout branch below.
 *  7. Phase B: hold the receive server open until the 60s deadline so the *slower* peer (who
 *     tapped Sync first or whose push attempts are arriving later) still has time to push to
 *     us and pull from us. Without this hold, the faster side's onCompletion stops the server
 *     within seconds and the slower side gets ConnectException for the rest of its window.
 *  8. onCompletion: release the lease taken in step 2, if any (covers success, error,
 *     cancellation, and timeout).
 *
 * [clock] defaults to the system clock in production; tests inject a clock driven by the
 * coroutine test scheduler so the retry ticks, the elapsed counter and the 60s deadline all
 * agree with virtual time.
 */
internal fun runSyncSession(
    host: String,
    trustedDevices: TrustedDevicesRepository,
    fingerprintService: FingerprintService,
    transferRepository: TransferRepository,
    push: suspend () -> Outcome<Unit>,
    pull: suspend () -> Outcome<Unit>,
    clock: Clock = Clock.System,
): Flow<SyncSessionState> {
    // The refcounted server's contract is "a lease is held if and only if startTransferServer()
    // returned normally". A failed start has already rolled its own lease back internally
    // (FileTransferRepository.startTransferServer), so onCompletion below must not call
    // stopTransferServer() unless this flag is true - doing so unconditionally, the way the old
    // unrefcounted server allowed, would release a lease this session never held and steal one
    // from whichever sibling artifact session (pgp/keystore) is still using the shared server.
    // That double-release is exactly the kind of teardown-out-from-under-a-sibling bug this whole
    // refcount exists to prevent. Declared out here, not inside the `flow { }` builder below, so
    // that the `.onCompletion { }` block chained onto it - a separate lambda, not nested inside
    // the builder's - can still see whether a lease was actually taken.
    //
    // That placement also makes it a variable of the returned Flow *instance*, not of one
    // collection of it - and a cold flow has to behave the same on its second collection as its
    // first (see `recordingOutcomes`'s identical `terminalRecorded` reset in this file, and its
    // KDoc, for the same shape). Without the `.onStart { }` reset below, a collection that starts
    // the server and completes normally would leave `started == true` in this closure; a later
    // second collection of that same Flow instance that fails verification or a start before ever
    // calling `startTransferServer()` would then have `onCompletion` release a lease it never
    // took - stealing one from whichever sibling artifact session (pgp/keystore) is still using
    // the shared server. Nothing in production collects the same instance twice today, but delete
    // this reset only if that stops being true and is being re-verified, not because it looks
    // redundant.
    var started = false

    return flow {
        emit(SyncSessionState.Idle)

        val verify = verifyTrustedFingerprint(host, trustedDevices, fingerprintService)
        if (!verify.isSuccessful()) {
            val err = verify as Outcome.Error
            emit(SyncSessionState.Error(err.cause, err.message))
            return@flow
        }

        try {
            // NonCancellable, not a plain suspend call: withContext still checks
            // ensureActive() on the way back out of its block, so if the collecting coroutine
            // was cancelled while startTransferServer() was suspended - a cancel or restart
            // landing in the middle of the bind, the single most common user action - the bind
            // could finish (lease taken, socket bound) and then withContext throws
            // CancellationException on resume *before* `started = true` ever runs. `started`
            // would then read false for a session that actually holds a lease, and onCompletion
            // below would never release it: a permanent leak, the same shape stopTransferServer's
            // own internal NonCancellable exists to prevent on the teardown side. The bind itself
            // is synchronous and bounded, so holding it uncancellable here costs nothing, and
            // onCompletion still runs and still releases once this coroutine finishes unwinding.
            withContext(NonCancellable) {
                transferRepository.startTransferServer()
                started = true
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // Never let a bind failure propagate: this flow is collected with no catch downstream, so
            // an uncaught exception here would kill the process rather than show the user an error.
            emit(
                SyncSessionState.Error(
                    TransferFailure.GeneralTransferFailure,
                    e.message ?: "Failed to start the receive server",
                ),
            )
            return@flow
        }
        emit(SyncSessionState.AwaitingPeer(host, elapsedSeconds = 0))

        val startMs = clock.now().toEpochMilliseconds()
        val deadlineMs = startMs + SYNC_TIMEOUT_SECONDS * 1_000L
        var lastError: Outcome.Error? = null
        var pushSucceeded = false
        var sessionSucceeded = false

        // One shared 60s budget covers both the push retries below and the pull retries that follow a
        // successful push. A second, pull-only deadline would let a session run up to 120s end to end.
        while (!sessionSucceeded && clock.now().toEpochMilliseconds() < deadlineMs) {
            if (!pushSucceeded) {
                when (val attempt = push()) {
                    is Outcome.Success -> {
                        pushSucceeded = true
                        emit(SyncSessionState.Syncing(host))
                        // Falls through to the pull attempt below within the same iteration.
                    }
                    is Outcome.Error -> {
                        lastError = attempt
                        if (attempt.cause is TransferFailure.PeerUnreachable) {
                            delay(retryDelayMs(clock, deadlineMs))
                            val elapsed = ((clock.now().toEpochMilliseconds() - startMs) / 1_000L).toInt()
                            emit(SyncSessionState.AwaitingPeer(host, elapsed))
                            continue
                        } else {
                            // Non-retryable (FingerprintMismatch, PublicKeyFetchFailure, etc.)
                            emit(SyncSessionState.Error(attempt.cause, attempt.message))
                            return@flow
                        }
                    }
                }
            }

            // pushSucceeded is true here, either from this iteration or a previous pull retry.
            when (val pullAttempt = pull()) {
                is Outcome.Success -> {
                    emit(SyncSessionState.Success(host))
                    // The chooser sorts by lastSyncedAt; stamping here is what keeps its
                    // top row and the fast path pointing at the device that actually works.
                    trustedDevices.getByHost(host)?.let { device ->
                        trustedDevices.updateLastSync(device.name, host, clock.now().toEpochMilliseconds())
                    }
                    sessionSucceeded = true
                }
                is Outcome.Error -> {
                    lastError = pullAttempt
                    if (pullAttempt.cause is TransferFailure.PeerUnreachable) {
                        // Retried silently: no new state is emitted here. The last state on screen is
                        // still Syncing, which is still an accurate description of what is happening -
                        // re-emitting AwaitingPeer (the "waiting to even start" state) would visibly
                        // regress the UI backwards after it already showed Syncing. Loop back to retry
                        // the pull only; the guard above ensures push() is never called again.
                        delay(retryDelayMs(clock, deadlineMs))
                    } else {
                        // A decrypt failure, an unpaired host or a refused handshake is an answer, not
                        // an absence - terminal on the spot, exactly like a non-retryable push error.
                        emit(SyncSessionState.Error(pullAttempt.cause, pullAttempt.message))
                        return@flow
                    }
                }
            }
        }

        if (!sessionSucceeded) {
            // The timeout has to tell the truth about which of two different things happened - both
            // exhaust the same retry loop above, but they are not the same claim. A non-retryable
            // failure on either side already returned above, so by construction the only way to reach
            // here is that every attempt that ran out the clock was PeerUnreachable.
            val error = if (!pushSucceeded) {
                // Every push attempt failed as PeerUnreachable: we never landed a single byte on the
                // peer. "Did not enter sync mode" is the honest read of this case.
                SyncSessionState.Error(
                    failure = TransferFailure.PeerSyncTimeout(host, reachedPeer = false),
                    message = lastError?.message ?: "Peer did not enter sync mode within ${SYNC_TIMEOUT_SECONDS}s",
                )
            } else {
                // The push succeeded - proof the peer's server was up and our vault may already be
                // sitting on it - and it was the pull retries that ran out the clock. Reporting this
                // as "did not enter sync mode" would be false, and that false sentence is exactly what
                // the sync activity log would persist as detail. reachedPeer=true is what lets
                // friendlyMessage (and RecordSyncOutcome, which calls it) tell the two cases apart.
                SyncSessionState.Error(
                    failure = TransferFailure.PeerSyncTimeout(host, reachedPeer = true),
                    message = peerReachedTimeoutMessage(host),
                )
            }
            emit(error)
            return@flow
        }

        // Phase B: hold the receive server up until the peer has completed its handshake with us
        // (one inbound push + one inbound sync-pull). Fall back to the original 60s deadline if the
        // peer never finishes (e.g. they hit a fingerprint mismatch or simply give up).
        val remainingMs = deadlineMs - clock.now().toEpochMilliseconds()
        if (remainingMs > 0) {
            withTimeoutOrNull(remainingMs) {
                transferRepository.peerHandshakeComplete.first { it }
            }
        }
    }.onStart {
        // Reset per collection, not per Flow instance - see the reset's rationale next to
        // `started`'s declaration above. Mirrors `recordingOutcomes`'s identical
        // `terminalRecorded` reset in this file.
        started = false
    }.onCompletion {
        if (started) transferRepository.stopTransferServer()
    }
}
