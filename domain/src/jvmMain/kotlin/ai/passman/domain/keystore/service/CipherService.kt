package ai.passman.domain.keystore.service

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.DecryptInfo
import ai.passman.domain.crypto.model.EncryptInfo
import ai.passman.domain.crypto.model.EncryptedData
import javax.crypto.Cipher

interface CipherService {

    // This method first gets or generates an instance of SecretKey and then initializes the Cipher
    // with the key
    suspend fun getInitializedCipherForEncryption(encryptInfo: EncryptInfo): Outcome<Cipher>

    // This method first gets or generates an instance of SecretKey and then initializes the Cipher
    // with the key
    suspend fun getInitializedCipherForDecryption(decryptInfo: DecryptInfo): Outcome<Cipher>

    // The Cipher created with getInitializedCipherForEncryption is used here
    suspend fun encryptData(plainData: ByteArray, cipher: Cipher): Outcome<EncryptedData>

    // The Cipher created with getInitializedCipherForDecryption is used here
    suspend fun decryptData(cipherData: ByteArray, cipher: Cipher): Outcome<ByteArray>
}
