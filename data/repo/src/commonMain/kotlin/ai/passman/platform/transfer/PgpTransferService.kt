package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome

interface PgpTransferService {
    suspend fun transferPgpBundle(
        decryptedBundleBytes: ByteArray,
        fileName: String,
        hostName: String,
        port: Int = 2323,
    ): Outcome<Unit>

    /** Pull the peer's PGP bundle DECRYPTED (post-quantum v3 on the wire). */
    suspend fun pullPgpBundle(
        hostName: String,
        port: Int = 2323,
    ): Outcome<ByteArray>
}
