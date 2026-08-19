package ai.passman.domain.settings.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.settings.model.ReconcileAction
import kotlinx.coroutines.flow.StateFlow

interface TransferRepository {
    suspend fun startTransferServer()
    suspend fun stopTransferServer()
    suspend fun isTransferServerRunning(): Boolean

    /**
     * Open/close the plaintext pairing listener (separate port from the TLS-only data server).
     * It serves the legacy RSA public key and the bounded public pairing-bundle exchange so a
     * not-yet-paired peer can compare identities during the explicit ceremony. Open it while the
     * pairing UI is visible; close it when the user leaves. No vault data crosses this listener.
     */
    suspend fun startPairingServer()
    suspend fun stopPairingServer()
    suspend fun getIpAddress(): String
    suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit>

    /**
     * True once the peer has both pushed to us and pulled from us during the current server
     * lifetime. Sync sessions use this to short-circuit their hold-open phase: once handshake
     * is complete, both sides have everything they need and the server can shut down early.
     *
     * Reset to false whenever the server starts fresh (i.e. `startTransferServer()` actually
     * starts a new server rather than no-op'ing on an already-running one).
     */
    val peerHandshakeComplete: StateFlow<Boolean>
}
