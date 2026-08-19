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
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
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
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
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
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
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
private const val PUSH_RETRY_INTERVAL_MS = 3_000L

/**
 * Drives a single bilateral Sync Mode session as a Flow. The caller cancels by cancelling
 * the collecting coroutine; `onCompletion` then tears down the receive server regardless of
 * how the flow ended (success, error, cancellation).
 *
 * Lifecycle:
 *  1. Verify peer fingerprint against any paired TrustedDevice. Mismatch -> emit Error and stop.
 *  2. Start receive server (idempotent).
 *  3. Phase A: push to peer every 3s for up to 60s. Emit AwaitingPeer ticks for the countdown.
 *  4. On first successful push -> pull from peer -> emit Success.
 *  5. Phase B: hold the receive server open until the 60s deadline so the *slower* peer (who
 *     tapped Sync first or whose push attempts are arriving later) still has time to push to
 *     us and pull from us. Without this hold, the faster side's onCompletion stops the server
 *     within seconds and the slower side gets ConnectException for the rest of its window.
 *  6. onCompletion: stop receive server (covers success, error, cancellation, and timeout).
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
): Flow<SyncSessionState> = flow {
    emit(SyncSessionState.Idle)

    val verify = verifyTrustedFingerprint(host, trustedDevices, fingerprintService)
    if (!verify.isSuccessful()) {
        val err = verify as Outcome.Error
        emit(SyncSessionState.Error(err.cause, err.message))
        return@flow
    }

    transferRepository.startTransferServer()
    emit(SyncSessionState.AwaitingPeer(host, elapsedSeconds = 0))

    val startMs = clock.now().toEpochMilliseconds()
    val deadlineMs = startMs + SYNC_TIMEOUT_SECONDS * 1_000L
    var lastError: Outcome.Error? = null
    var pushedAndPulled = false

    // Phase A: retry push until success or timeout
    while (!pushedAndPulled && clock.now().toEpochMilliseconds() < deadlineMs) {
        when (val attempt = push()) {
            is Outcome.Success -> {
                emit(SyncSessionState.Syncing(host))
                val pullOutcome = pull()
                if (pullOutcome.isSuccessful()) {
                    emit(SyncSessionState.Success(host))
                    // The chooser sorts by lastSyncedAt; stamping here is what keeps its
                    // top row and the fast path pointing at the device that actually works.
                    trustedDevices.getByHost(host)?.let { device ->
                        trustedDevices.updateLastSync(device.name, host, clock.now().toEpochMilliseconds())
                    }
                    pushedAndPulled = true
                } else {
                    val err = pullOutcome as Outcome.Error
                    emit(SyncSessionState.Error(err.cause, err.message))
                    return@flow
                }
            }
            is Outcome.Error -> {
                lastError = attempt
                if (attempt.cause is TransferFailure.PeerUnreachable) {
                    delay(PUSH_RETRY_INTERVAL_MS)
                    val elapsed = ((clock.now().toEpochMilliseconds() - startMs) / 1_000L).toInt()
                    emit(SyncSessionState.AwaitingPeer(host, elapsed.coerceAtMost(SYNC_TIMEOUT_SECONDS)))
                } else {
                    // Non-retryable (FingerprintMismatch, PublicKeyFetchFailure, etc.)
                    emit(SyncSessionState.Error(attempt.cause, attempt.message))
                    return@flow
                }
            }
        }
    }

    if (!pushedAndPulled) {
        // Timed out before we ever reached the peer
        val isUnreachable = lastError?.cause is TransferFailure.PeerUnreachable
        emit(
            SyncSessionState.Error(
                failure = if (isUnreachable || lastError == null) TransferFailure.PeerSyncTimeout(host) else lastError!!.cause,
                message = lastError?.message ?: "Peer did not enter sync mode within ${SYNC_TIMEOUT_SECONDS}s",
            ),
        )
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
}.onCompletion {
    transferRepository.stopTransferServer()
}
