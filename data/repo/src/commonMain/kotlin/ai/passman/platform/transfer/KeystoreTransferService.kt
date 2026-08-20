package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice

interface KeystoreTransferService {
    /**
     * Send to [device], the record the sync-target chooser handed the session — see
     * [PasswordTransferService.transferDatabaseBytes] for why the record travels rather than its
     * address.
     */
    suspend fun transferKeystoreBundle(
        decryptedBundleBytes: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int = 2323,
    ): Outcome<Unit>

    /** Pull [device]'s keystore bundle DECRYPTED (post-quantum v3 on the wire). */
    suspend fun pullKeystoreBundle(
        device: TrustedDevice,
        port: Int = 2323,
    ): Outcome<ByteArray>
}
