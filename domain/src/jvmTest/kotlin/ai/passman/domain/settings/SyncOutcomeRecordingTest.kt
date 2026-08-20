package ai.passman.domain.settings

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.keystore.FakeKeystoreRepository
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.persistence.InMemoryKeystoreEventPersistence
import ai.passman.domain.password.FakePasswordRepository
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.InMemoryPasswordEventPersistence
import ai.passman.domain.pgp.FakePgpRepository
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.InMemoryPgpEventPersistence
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.model.SyncSessionState
import ai.passman.domain.settings.repository.SyncLogRepository
import ai.passman.domain.settings.repository.TransferRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

/**
 * The three sync wrappers ([SyncPasswords], [SyncPgpKeys], [SyncKeystores]) each know their own
 * artifact statically and are where recording is wired in — `runSyncSession` itself is shared and
 * has no way to know which one it is running for. These tests exercise the wrappers end to end
 * (through the real [RecordSyncOutcome] and a fake [SyncLogRepository]) rather than
 * `recordTerminalState` in isolation, because the risk this covers is a wiring mistake — an
 * artifact or host that got threaded through wrong, or a wrapper where recording was never wired
 * in at all (obligation 8).
 *
 * `RecordSyncOutcomeTest` covers `RecordSyncOutcome`'s own logic (device-name resolution, the
 * "never fail a sync" swallow) in isolation; that coverage is not repeated here per outcome.
 */
class SyncOutcomeRecordingTest {

    // region: obligation 1 — success

    @Test
    fun `a successful passwords session appends exactly one success record with the resolved device name`() =
        runTest {
            val log = RecordingTestSyncLog()
            val transfer = RecordingTestTransferRepository()
            val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
            val passwordEvents = InMemoryPasswordEventPersistence(UnconfinedFacade)
            val sync = SyncPasswords(
                passwordRepository = FakePasswordRepository(
                    push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                    pull = { Outcome.Success(Unit) },
                ),
                transferRepository = transfer,
                trustedDevices = trusted,
                fingerprintService = UnusedFingerprintService,
                passwordEventPersistence = passwordEvents,
                recordSyncOutcome = RecordSyncOutcome(log),
            )

            val states = sync(PAIRED_DEVICE).toList()

            assertIs<SyncSessionState.Success>(states.last())
            val entry = log.appended.single()
            assertEquals(SyncOps.PASSWORDS, entry.artifact)
            assertEquals(SyncLogEntry.OUTCOME_SUCCESS, entry.outcome)
            assertEquals(PAIRED_DEVICE.name, entry.deviceName)
        }

    /** Obligation 8: PGP keys must record too, not just passwords. */
    @Test
    fun `a successful pgp keys session records with the pgp artifact`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPgpKeys(
            pgpRepository = FakePgpRepository(
                push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                pull = { Outcome.Success(Unit) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            pgpEventPersistence = InMemoryPgpEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        sync(PAIRED_DEVICE).toList()

        val entry = log.appended.single()
        assertEquals(SyncOps.PGP, entry.artifact)
        assertEquals(SyncLogEntry.OUTCOME_SUCCESS, entry.outcome)
    }

    /** Obligation 8: keystores must record too, not just passwords. */
    @Test
    fun `a successful keystores session records with the keystore artifact`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncKeystores(
            keystoreRepository = FakeKeystoreRepository(
                push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                pull = { Outcome.Success(Unit) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            keystoreEventPersistence = InMemoryKeystoreEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        sync(PAIRED_DEVICE).toList()

        val entry = log.appended.single()
        assertEquals(SyncOps.KEYSTORE, entry.artifact)
        assertEquals(SyncLogEntry.OUTCOME_SUCCESS, entry.outcome)
    }

    // endregion

    // region: obligation 2 — failed vs cancelled

    @Test
    fun `a failed session records the friendly message as detail, not the raw failure`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { Outcome.Error("no public key", TransferFailure.PublicKeyFetchFailure) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        val states = sync(PAIRED_DEVICE).toList()

        assertIs<SyncSessionState.Error>(states.last())
        val entry = log.appended.single()
        assertEquals(SyncLogEntry.OUTCOME_FAILED, entry.outcome)
        assertEquals(
            friendlyMessage(TransferFailure.PublicKeyFetchFailure, "no public key"),
            entry.detail,
            "a logged failure must read the same as the snackbar the user saw at the time",
        )
    }

    @Test
    fun `a cancelled session records cancelled, not failed`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { Outcome.Error("cancelled by user", TransferFailure.SyncCancelled) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        sync(PAIRED_DEVICE).toList()

        val entry = log.appended.single()
        assertEquals(
            SyncLogEntry.OUTCOME_CANCELLED,
            entry.outcome,
            "SyncCancelled must be its own outcome, not folded into a generic failure",
        )
    }

    // endregion

    // region: obligation 4 — recording must never change the sync's own outcome

    @Test
    fun `a storage failure while recording a success does not change the reported sync outcome`() = runTest {
        val log = RecordingTestSyncLog(throwOnAppend = IllegalStateException("disk full"))
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val passwordEvents = InMemoryPasswordEventPersistence(UnconfinedFacade)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                pull = { Outcome.Success(Unit) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = passwordEvents,
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        // Must not throw: a broken log store must not surface as a broken sync.
        val states = sync(PAIRED_DEVICE).toList()

        assertIs<SyncSessionState.Success>(states.last(), "the user's own sync outcome must be untouched")
    }

    @Test
    fun `a storage failure while recording a failure does not change the reported error`() = runTest {
        val log = RecordingTestSyncLog(throwOnAppend = IllegalStateException("disk full"))
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { Outcome.Error("no public key", TransferFailure.PublicKeyFetchFailure) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        val states = sync(PAIRED_DEVICE).toList()

        val terminal = assertIs<SyncSessionState.Error>(states.last())
        assertIs<TransferFailure.PublicKeyFetchFailure>(terminal.failure)
    }

    // endregion

    // region: review finding 1 — a real (out-of-band) cancellation must still record cancelled

    /**
     * Reproduces the actual shape of cancellation in production — `syncJob?.cancel()` on the
     * coroutine collecting this flow (`PasswordHomeViewModel.onSyncClick`, `:125`) — rather than
     * the shape [TransferFailure.SyncCancelled] tests fake. `push` succeeds first, exactly like a
     * user who cancels during `pull` after their vault is already on the peer: no
     * [SyncSessionState.Error] carrying [TransferFailure.SyncCancelled] is ever emitted, because
     * nothing in production constructs one, so this is the only kind of test that can tell whether
     * a genuine cancellation gets recorded at all rather than merely mapped correctly once it
     * arrives in the shape a fake chose for it.
     */
    @Test
    fun `a coroutine cancelled during a real pull still appends a cancelled record, not nothing`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val pullStarted = CompletableDeferred<Unit>()
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                pull = {
                    pullStarted.complete(Unit)
                    awaitCancellation() // stands in for a pull that is still in flight when cancelled
                },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        val collector = launch { sync(PAIRED_DEVICE).toList() }
        pullStarted.await()
        collector.cancel()
        collector.join()

        val entry = log.appended.single()
        assertEquals(
            SyncLogEntry.OUTCOME_CANCELLED,
            entry.outcome,
            "a real cancellation mid-session must be recorded, not silently dropped",
        )
        assertEquals(SyncOps.PASSWORDS, entry.artifact)
    }

    // endregion

    // region: pull-retry plan (2026-08-19) obligation 14 — a pull-side terminal failure must record too
    //
    // Every failure recorded above is a push-side failure. `recordTerminalState` only looks at the
    // terminal `SyncSessionState`, not at which phase produced it, so nothing here was ever
    // actually at risk of missing a pull-side failure by construction - but that is exactly the
    // kind of "obviously fine" gap the pull-retry work found once pulls became retryable, and it is
    // cheap enough to pin directly rather than trust the inference.

    @Test
    fun `a non-retryable pull failure after a successful push is recorded as failed`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { Outcome.Success(Unit) },
                pull = { Outcome.Error("payload did not decrypt", TransferFailure.GeneralTransferFailure) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        val states = sync(PAIRED_DEVICE).toList()

        assertIs<SyncSessionState.Error>(states.last())
        val entry = log.appended.single()
        assertEquals(SyncLogEntry.OUTCOME_FAILED, entry.outcome)
        assertEquals(
            friendlyMessage(TransferFailure.GeneralTransferFailure, "payload did not decrypt"),
            entry.detail,
            "a pull-side failure must be logged exactly like a push-side one - same detail, same outcome",
        )
    }

    /**
     * The other half of "tell the truth on timeout" (`SyncPasswords.runSyncSession`): once the push
     * has landed, a pull that keeps failing as [TransferFailure.PeerUnreachable] until the shared
     * deadline must not persist "did not enter sync mode" - that sentence is false once the push
     * succeeded, and this is the exact detail string [RecordSyncOutcome] would otherwise turn into
     * a permanent, false record of a sync that partially worked.
     */
    @Test
    fun `a reached-then-lost pull timeout records the truthful detail, not the never-reached message`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { Outcome.Success(Unit) },
                pull = { Outcome.Error("peer unreachable: connection refused", TransferFailure.PeerUnreachable(HOST)) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
            // The session's retry delays are virtual under runTest, so its deadline has to be read
            // from the same virtual clock. On the system clock the loop spins in real time until
            // the harness kills the test a minute later.
            clock = SchedulerClock(testScheduler),
        )

        val states = sync(PAIRED_DEVICE).toList()

        val terminal = assertIs<SyncSessionState.Error>(states.last())
        val failure = assertIs<TransferFailure.PeerSyncTimeout>(terminal.failure)
        assertTrue(failure.reachedPeer, "the push landed before the pull retries ran out the clock")

        val entry = log.appended.single()
        assertEquals(SyncLogEntry.OUTCOME_FAILED, entry.outcome)
        assertFalse(
            entry.detail.contains("did not enter sync mode"),
            "the push succeeded - our vault may already be on the peer - so the persisted detail must " +
                "not claim the peer was never reached",
        )
        assertTrue(
            entry.detail.contains("already be on the peer"),
            "the persisted detail must say the data may already have landed on the peer",
        )
    }

    // endregion

    // region: the log row must name the device the session was given

    /**
     * The device name on a log row used to be resolved from the row's host, with
     * `TrustedDevicesRepository.getByHost` - a first match over an address two pairings can share.
     * Re-pairing the same physical peer under a new name is enough to produce that pair (same host,
     * same fingerprint, two rows), and the log would then attribute the sync to whichever of them
     * came first in the store rather than to the one the user tapped.
     *
     * The decoy is deliberately first here, so a resolution that still went through the host would
     * name it. Nothing in [RecordSyncOutcome] resolves anything any more, and this is what holds
     * that: the name written is the name the session carried in.
     */
    @Test
    fun `the log names the device the session was given, not another pairing at the same address`() = runTest {
        val log = RecordingTestSyncLog()
        val transfer = RecordingTestTransferRepository()
        val trusted = RecordingTestTrustedDevices(SAME_HOST_DECOY, PAIRED_DEVICE)
        val sync = SyncPasswords(
            passwordRepository = FakePasswordRepository(
                push = { transfer.handshake.value = true; Outcome.Success(Unit) },
                pull = { Outcome.Success(Unit) },
            ),
            transferRepository = transfer,
            trustedDevices = trusted,
            fingerprintService = UnusedFingerprintService,
            passwordEventPersistence = InMemoryPasswordEventPersistence(UnconfinedFacade),
            recordSyncOutcome = RecordSyncOutcome(log),
        )

        val states = sync(PAIRED_DEVICE).toList()

        assertIs<SyncSessionState.Success>(states.last())
        val entry = log.appended.single()
        assertEquals(
            PAIRED_DEVICE.name,
            entry.deviceName,
            "the row must name the tapped device, not '${SAME_HOST_DECOY.name}' - the record a " +
                "by-host resolution would have found first",
        )
        assertEquals(HOST, entry.host)
    }

    // endregion

    // region: harness

    private companion object {
        const val HOST = "192.0.2.42"
        val PAIRED_DEVICE = TrustedDevice(name = "laptop", fingerprint = "AA:BB:CC", lastHost = HOST)

        /** The same physical peer re-paired under a new name: same host, same fingerprint, new row. */
        val SAME_HOST_DECOY = TrustedDevice(name = "laptop-re-paired", fingerprint = "AA:BB:CC", lastHost = HOST)
    }

    // endregion
}

private class RecordingTestSyncLog(private val throwOnAppend: Throwable? = null) : SyncLogRepository {
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

private class RecordingTestTrustedDevices(private val devices: List<TrustedDevice>) : TrustedDevicesRepository {
    constructor(device: TrustedDevice?) : this(listOfNotNull(device))
    constructor(vararg devices: TrustedDevice) : this(devices.toList())

    override fun observeAll(): Flow<List<TrustedDevice>> = emptyFlow()
    override suspend fun getAll(): List<TrustedDevice> = devices
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner) = true
    override suspend fun remove(name: String) = Unit
    /** Mirrors production: one match or nothing, never a first match. */
    override suspend fun getByHost(host: String): TrustedDevice? =
        devices.filter { it.lastHost == host }.singleOrNull()
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = Unit
    override suspend fun updateHost(name: String, host: String) = Unit
    override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = Unit
    override suspend fun markSignedHybridPairingsForReverification() = Unit
}

private class RecordingTestTransferRepository : TransferRepository {
    val handshake = MutableStateFlow(false)
    override val peerHandshakeComplete: StateFlow<Boolean> get() = handshake

    override suspend fun startTransferServer() = Unit
    override suspend fun stopTransferServer() = Unit
    override suspend fun isTransferServerRunning(): Boolean = true
    override suspend fun startPairingServer() = Unit
    override suspend fun stopPairingServer() = Unit
    override suspend fun getIpAddress(): String = "127.0.0.1"
    override suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit> =
        Outcome.Success(Unit)
}

/** The session never touches the fingerprint service (mTLS SPKI pinning binds the channel instead). */
private object UnusedFingerprintService : FingerprintService {
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

    private fun unused(): Nothing = error("the sync session must not touch FingerprintService")
}

private object UnconfinedFacade : CoroutinesContextFacade {
    override val io = Dispatchers.Unconfined
    override val main = Dispatchers.Unconfined
    override val default = Dispatchers.Unconfined
    override val unconfined = Dispatchers.Unconfined
    override val errorHandler = Dispatchers.Unconfined
}
