package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice

interface PasswordTransferService {
    /**
     * Send to a **typed** address (Settings > Transfer). The implementation resolves it to the one
     * pairing that claims it and refuses an address more than one pairing claims — there is no
     * chosen device on this path to carry, and a first match would pin an arbitrary one of two
     * indistinguishable pairings.
     */
    suspend fun transferDatabaseBytes(
        decryptedDatabaseBytes: ByteArray,
        fileName: String,
        hostName: String,
        port: Int = 2323,
    ): Outcome<Unit>

    /**
     * Send to [device], the record the sync-target chooser handed the session.
     *
     * The record travels rather than [TrustedDevice.lastHost] because the transport pins the peer's
     * SPKI from whatever device it is given, and two pairings can legitimately hold the same host —
     * so re-deriving the device from an address here could pin a pairing the user never chose.
     */
    suspend fun transferDatabaseBytes(
        decryptedDatabaseBytes: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int = 2323,
    ): Outcome<Unit>

    /**
     * Pull [device]'s password DB and return it DECRYPTED. The wire transfer is post-quantum
     * (suite v3): the implementation sends its own hybrid public key and decrypts the response with
     * its hybrid private key. Empty ByteArray when the peer has no DB; Outcome.Error on network fail.
     */
    suspend fun pullDatabase(
        device: TrustedDevice,
        port: Int = 2323,
    ): Outcome<ByteArray>
}
