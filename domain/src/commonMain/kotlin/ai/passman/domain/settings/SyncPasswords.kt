package ai.passman.domain.settings

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
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
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.domain.settings.repository.TransferRepository
import kotlin.time.Clock
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.withTimeoutOrNull

class SyncPasswords(
    private val passwordRepository: PasswordRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val passwordEventPersistence: PasswordEventPersistence,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        push = { passwordRepository.pushPasswordDatabase(host) },
        pull = { passwordRepository.pullPasswordDatabase(host) },
    ).onEach { state ->
        if (state is SyncSessionState.Success) {
            passwordEventPersistence.update(PasswordEvent.Updated)
        }
    }
}

class SyncPgpKeys(
    private val pgpRepository: ai.passman.domain.pgp.repository.PgpRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val pgpEventPersistence: PgpEventPersistence,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        push = { pgpRepository.pushPgpKeys(host) },
        pull = { pgpRepository.pullPgpKeys(host) },
    ).onEach { state ->
        if (state is SyncSessionState.Success) {
            pgpEventPersistence.update(PgpEvent.KeyModified)
        }
    }
}

class SyncKeystores(
    private val keystoreRepository: ai.passman.domain.keystore.repository.KeystoreRepository,
    private val transferRepository: TransferRepository,
    private val trustedDevices: TrustedDevicesRepository,
    private val fingerprintService: FingerprintService,
    private val keystoreEventPersistence: KeystoreEventPersistence,
) {
    operator fun invoke(host: String): Flow<SyncSessionState> = runSyncSession(
        host = host,
        trustedDevices = trustedDevices,
        fingerprintService = fingerprintService,
        transferRepository = transferRepository,
        push = { keystoreRepository.pushKeystores(host) },
        pull = { keystoreRepository.pullKeystores(host) },
    ).onEach { state ->
        if (state is SyncSessionState.Success) {
            keystoreEventPersistence.update(KeystoreEvent.Updated)
        }
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
