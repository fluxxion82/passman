package ai.passman.crypto

import java.io.File
import java.security.Key

/**
 * Thin facade over [CryptoEnvelope] for the remaining `encrypt/decryptDatabase*` call sites (the vault
 * at-rest path and the transfer receive boundary). All actual work goes through the versioned envelope,
 * so callers write the authenticated v2 suite (AES-256-GCM + RSA-OAEP) and transparently read legacy v1.
 */
object Crypto {
    fun encryptDatabase(messageData: ByteArray, encryptedFile: File, publicKey: Key) {
        encryptedFile.writeBytes(encryptDatabaseBytes(messageData, publicKey))
    }

    fun decryptDatabase(encryptedFile: File, privateKey: Key): ByteArray =
        decryptDatabaseBytes(encryptedFile.readBytes(), privateKey)

    fun encryptDatabaseBytes(messageData: ByteArray, publicKey: Key): ByteArray =
        CryptoEnvelope.encrypt(messageData, publicKey)

    fun decryptDatabaseBytes(encryptedDataBytes: ByteArray, privateKey: Key): ByteArray =
        CryptoEnvelope.decrypt(encryptedDataBytes, privateKey)
}
