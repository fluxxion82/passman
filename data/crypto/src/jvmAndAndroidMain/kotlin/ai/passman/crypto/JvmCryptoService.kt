package ai.passman.crypto

class JvmCryptoService : CryptoService {
    override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray =
        Crypto.encryptDatabaseBytes(plain, publicKey.key)

    override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray =
        Crypto.decryptDatabaseBytes(cipher, privateKey.key)
}
