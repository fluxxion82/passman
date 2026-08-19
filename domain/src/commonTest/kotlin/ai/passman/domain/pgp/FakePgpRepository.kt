package ai.passman.domain.pgp

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.model.PgpKeyAlgorithm
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.SubKeyAction
import ai.passman.domain.pgp.model.UserId
import ai.passman.domain.pgp.model.UserIdAction
import ai.passman.domain.pgp.repository.PgpRepository

/**
 * Hand-written stand-in for [PgpRepository].
 *
 * These tests live in commonTest and therefore compile for iOS and JS as well as the JVM,
 * so a JVM-only mocking framework is not an option — the original versions of these tests
 * were written against mockk and could never have run here.
 *
 * Only the methods the use-cases under test actually call are given behaviour. Everything
 * else fails loudly rather than silently returning a default, so a test that strays outside
 * what it set up gets an obvious error instead of a confusing assertion failure.
 */
class FakePgpRepository(
    private val encrypt: (plainText: String) -> Outcome<String> = { unsupported("encryptPgpMessage") },
    private val encryptFile: (filePath: String) -> Outcome<String> = { unsupported("encryptPgpFile") },
    private val decrypt: (encryptedText: String) -> Outcome<String> = { unsupported("decryptPgpMessage") },
    private val decryptFile: (path: String) -> Outcome<String> = { unsupported("decryptPgpFile") },
    private val importDeveloperKey: (force: Boolean) -> Outcome<Boolean> = { unsupported("importBundledDeveloperKey") },
    private val keys: () -> List<PgpKeyPair> = { unsupported("getKeys") },
    private val createDefaultRings: suspend (passphrase: String) -> Outcome<Unit> =
        { unsupported("createDefaultKeyRings") },
    private val deleteDefaultRings: () -> Outcome<Unit> = { unsupported("deleteDefaultKeyRings") },
) : PgpRepository {

    val encryptCalls = mutableListOf<Pair<String, String>>()
    val decryptCalls = mutableListOf<Triple<String, String, String>>()
    val importDeveloperKeyCalls = mutableListOf<Boolean>()
    val createDefaultRingCalls = mutableListOf<String>()
    var deleteDefaultRingCalls = 0
        private set

    override suspend fun encryptPgpMessage(plainText: String, publicKeyPath: String): Outcome<String> {
        encryptCalls += plainText to publicKeyPath
        return encrypt(plainText)
    }

    override suspend fun encryptPgpFile(filePath: String, publicKeyPath: String): Outcome<String> {
        encryptCalls += filePath to publicKeyPath
        return encryptFile(filePath)
    }

    override suspend fun decryptPgpMessage(
        encryptedText: String,
        secretKeyPath: String,
        keyPassword: String,
    ): Outcome<String> {
        decryptCalls += Triple(encryptedText, secretKeyPath, keyPassword)
        return decrypt(encryptedText)
    }

    override suspend fun decryptPgpFile(
        encryptedFilePath: String,
        secretKeyPath: String,
        keyPassword: String,
    ): Outcome<String> {
        decryptCalls += Triple(encryptedFilePath, secretKeyPath, keyPassword)
        return decryptFile(encryptedFilePath)
    }

    override suspend fun getKeys(): List<PgpKeyPair> = keys()
    override suspend fun getKey(keyId: Long): PgpKeyPair? = unsupported("getKey")
    override suspend fun getPublicKeyPath(keyId: Long): Outcome<String> = unsupported("getPublicKeyPath")
    override suspend fun getSecretKeyPath(keyId: Long, passphrase: String): Outcome<String> =
        unsupported("getSecretKeyPath")
    override suspend fun createPgpKey(
        name: String,
        email: String,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long,
    ): Outcome<String> = unsupported("createPgpKey")

    override suspend fun clearSign(plainText: String, privateKeyPath: String, keyPassword: String): Outcome<String> =
        unsupported("clearSign")

    override suspend fun clearSignFile(
        plainFilePath: String,
        privateKeyPath: String,
        keyPassword: String,
    ): Outcome<String> = unsupported("clearSignFile")

    override suspend fun sign(
        plainText: String,
        privateKeyPath: String,
        passPhrase: String,
        armor: Boolean,
        digestName: String,
    ): Outcome<String> = unsupported("sign")

    override suspend fun verifyClearSignature(encryptedText: String, publicKeyPath: String): Outcome<Unit> =
        unsupported("verifyClearSignature")

    override suspend fun verifyClearSignatureFile(encryptedFilePath: String, publicKeyPath: String): Outcome<Unit> =
        unsupported("verifyClearSignatureFile")

    override suspend fun verifySignature(signatureText: String, publicKeyPath: String): Outcome<Unit> =
        unsupported("verifySignature")

    override suspend fun signAndEncrypt(
        plainText: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String,
    ): Outcome<String> = unsupported("signAndEncrypt")

    override suspend fun signAndEncryptFile(
        plainFilePath: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String,
    ): Outcome<String> = unsupported("signAndEncryptFile")

    override suspend fun verifyAndDecrypt(
        encryptedText: String,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String,
    ): Outcome<String> = unsupported("verifyAndDecrypt")

    override suspend fun verifyAndDecryptFile(
        encryptedFilePath: String,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String,
    ): Outcome<String> = unsupported("verifyAndDecryptFile")

    override suspend fun modifyUserId(
        keyPair: PgpKeyPair,
        password: String,
        userId: UserId,
        userIdAction: UserIdAction,
    ): Outcome<Unit> = unsupported("modifyUserId")

    override suspend fun addSubKey(
        keyPair: PgpKeyPair,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long,
    ): Outcome<Unit> = unsupported("addSubKey")

    override suspend fun modifySubKey(
        keyPair: PgpKeyPair,
        password: String,
        subKeyId: String,
        action: SubKeyAction,
    ): Outcome<Unit> = unsupported("modifySubKey")

    override suspend fun changeKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long) =
        unsupported("changeKeyExpiry")

    override suspend fun changeSubKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long) =
        unsupported("changeSubKeyExpiry")

    override suspend fun changeKeyPassword(
        keyPair: PgpKeyPair,
        oldPassword: String,
        newPassword: String,
    ): Outcome<Unit> = unsupported("changeKeyPassword")

    override suspend fun importPgpFile(path: String): Outcome<Unit> = unsupported("importPgpFile")
    override suspend fun importBundledDeveloperKey(force: Boolean): Outcome<Boolean> {
        importDeveloperKeyCalls += force
        return importDeveloperKey(force)
    }
    override suspend fun deletePgpKey(keyId: Long): Outcome<Unit> = unsupported("deletePgpKey")

    override suspend fun createDefaultKeyRings(passphrase: String): Outcome<Unit> {
        createDefaultRingCalls += passphrase
        return createDefaultRings(passphrase)
    }

    override suspend fun deleteDefaultKeyRings(): Outcome<Unit> {
        deleteDefaultRingCalls += 1
        return deleteDefaultRings()
    }

    override suspend fun transferPgpKeys(hostName: String): Outcome<Unit> = unsupported("transferPgpKeys")
    override suspend fun pushPgpKeys(hostName: String): Outcome<Unit> = unsupported("pushPgpKeys")
    override suspend fun pullPgpKeys(hostName: String): Outcome<Unit> = unsupported("pullPgpKeys")

    companion object {
        private fun unsupported(name: String): Nothing =
            throw UnsupportedOperationException("FakePgpRepository.$name was not configured for this test")
    }
}
