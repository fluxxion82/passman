package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome

interface KeystoreTransferService {
    suspend fun transferKeystoreBundle(
        decryptedBundleBytes: ByteArray,
        fileName: String,
        hostName: String,
        port: Int = 2323,
    ): Outcome<Unit>

    /** Pull the peer's keystore bundle DECRYPTED (post-quantum v3 on the wire). */
    suspend fun pullKeystoreBundle(
        hostName: String,
        port: Int = 2323,
    ): Outcome<ByteArray>
}
