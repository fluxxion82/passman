package ai.passman.platform.transfer

import ai.passman.domain.base.model.Outcome

interface PasswordTransferService {
    suspend fun transferDatabaseBytes(
        decryptedDatabaseBytes: ByteArray,
        fileName: String,
        hostName: String,
        port: Int = 2323,
    ): Outcome<Unit>

    /**
     * Pull the peer's password DB and return it DECRYPTED. The wire transfer is post-quantum
     * (suite v3): the implementation sends its own hybrid public key and decrypts the response with
     * its hybrid private key. Empty ByteArray when the peer has no DB; Outcome.Error on network fail.
     */
    suspend fun pullDatabase(
        hostName: String,
        port: Int = 2323,
    ): Outcome<ByteArray>
}
