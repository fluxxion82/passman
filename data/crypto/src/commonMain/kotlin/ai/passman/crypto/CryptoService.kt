package ai.passman.crypto

interface CryptoService {
    fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray
    fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray
}
