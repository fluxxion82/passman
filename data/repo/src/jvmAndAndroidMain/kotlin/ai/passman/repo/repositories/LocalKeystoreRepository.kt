package ai.passman.repo.repositories

import ai.passman.crypto.Crypto
import ai.passman.crypto.CryptoKey
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.keystore.KeystoreClient
import ai.passman.keystore.model.Keystore
import ai.passman.cache.KeyCacheManager
import ai.passman.cache.CachedKeystoreKey
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.platform.transfer.KeystoreTransferService
import ai.passman.repo.Platform
import ai.passman.repo.createNewFileWithAppendedName
import ai.passman.repo.di.KEYSTORE_CACHE
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.cache.di.keystoreCacheScope
import ai.passman.cache.di.passmanSessionScope
import ai.passman.cache.di.closeKeystoreCacheScope
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.CreateKeyStore
import ai.passman.domain.keystore.exception.KeystoreFailure
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.repository.KeystoreRepository
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.Key
import java.util.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import org.koin.core.qualifier.named
import org.koin.mp.KoinPlatform

class LocalKeystoreRepository(
    private val platform: Platform,
    private val userPreferences: UserPreferences,
    private val keyStoreClient: KeystoreClient,
    private val coroutinesContextFacade: CoroutinesContextFacade,
    private val keystoreTransferService: KeystoreTransferService,
): KeystoreRepository {
    private var keystoreSession: String = ""

    private val keystoreDir = "${platform.getLocalPath()}${File.separator}keystore${File.separator}"

    override suspend fun createKeyStore(request: CreateKeyStore.CreateRequest): Outcome<KeyStoreInfo> =
        withContext(coroutinesContextFacade.io) {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            // keystoreDir already ends in a separator; appending another used to produce a
            // double-separator path that only worked because java.io.File normalizes it.
            val keystorePath = "$keystoreDir${user.userName}"
            // The returned name must carry the extension: getAllKeystores lists file names WITH
            // it, and callers compare the two.
            val fileName =
                if (request.keystoreName.endsWith(".pfx")) request.keystoreName else "${request.keystoreName}.pfx"
            // One client call, one PKCS#12 store(): the key goes in before the file is first
            // written, and a failure anywhere leaves no empty store file behind.
            val result = keyStoreClient.createKeyStore(
                keystoreType = request.keystoreType,
                keystorePassword = request.keystorePassword,
                keystoreName = fileName,
                keystorePath = keystorePath,
                initialKey = KeystoreKey(
                    keyAlias = request.keyAlias,
                    keyPassword = request.aliasPassword,
                    keyAlgorithm = request.keyAlgorithm,
                ),
            )
            if (result.isSuccess) {
                Outcome.Success(
                    KeyStoreInfo(
                        path = keystorePath,
                        name = fileName,
                        keystorePassword = request.keystorePassword,
                        listOf(
                            KeystoreKey(
                                keyAlias = request.keyAlias,
                                keyPassword = request.aliasPassword,
                                keyAlgorithm = request.keyAlgorithm,
                            )
                        ),
                        type = KeyStoreType.PKCS12,
                    )
                )
            } else {
                Outcome.Error("failed to create key ring", KeystoreFailure.CreateKeystore)
            }
        }

    override suspend fun importKeystoreFile(filepath: String): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val source = Paths.get(filepath)
            val destinationPath = "$keystoreDir${user.userName}${File.separator}${source.fileName}"
            val destination = Paths.get(destinationPath)

            // The per-user dir otherwise only exists once a keystore has been saved; importing
            // into a fresh account must not depend on that.
            destination.parent?.let { Files.createDirectories(it) }
            Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING)

            Outcome.Success(Unit)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to copy import file" }
        }.getOrElse {
            Outcome.Error("failed to import file", PgpFailure.ImportKeyFailure)
        }
    }

    override suspend fun loadKeystore(path: String, name: String): KeyStoreInfo? = withContext(coroutinesContextFacade.io) {
        val stores = getAllKeystores()
        stores.find {
            it.path == path && it.name == name
        }.also {
            if (it != null) {
                keystoreSession = UUID.randomUUID().toString()
            }
        }
    }

    override suspend fun getAllKeystores(): List<KeyStoreInfo> = withContext(coroutinesContextFacade.io) {
        val user = userPreferences.getUser() as AppUser.LoggedIn
        val keysPath = "$keystoreDir${user.userName}"
        clearKeyStore()

        val keyFiles = File(keysPath).listFiles { file ->
            file.isFile &&
                file.name != "${user.userName}.pfx" &&
                file.name != DirectoryBundler.portableRecoveryP12Name(user.userName) &&
                file.extension in listOf("pfx", "jks", "bks", "p12", "pem", "kdb", "udb", "ss12", "keystore")
        }?.map {
            KeyStoreInfo(
                path = it.path.split(File.separator).dropLast(1).joinToString(File.separator.toString()),
                name = it.name,
                keystorePassword = "",
                keyList  = listOf(),
                type = KeyStoreType.PKCS12, // only working with this format for now
            )
        }

        keyFiles.orEmpty()
    }

    override suspend fun getAliases(path: String, keystoreName: String, password: String): Outcome<List<KeystoreKey>> =
        withContext(coroutinesContextFacade.io) {
            if (keystoreSession.isEmpty()) {
                return@withContext Outcome.Error("no longer in keystore session", KeystoreFailure.GetAliasesFailure)
            }
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                val info = keyStoreClient.getKeyStoreInfo(Keystore(path, keystoreName, password))
                if (info.isSuccess) {
                    val keyStore = info.getOrNull()
                    keyCacheManager.keyStore = keyStore
                    val keys = keyStore?.aliases()?.toList()?.map { alias ->
                        val publicKey: Key? = keyStore.getCertificate(alias)?.publicKey
                        val algorithm = when {
                            publicKey?.algorithm == "RSA" -> KeystoreKeyAlgorithm.RSA
                            keyStore.isKeyEntry(alias) && keyStore.getCertificate(alias) == null -> KeystoreKeyAlgorithm.AES
                            else -> KeystoreKeyAlgorithm.UNKNOWN
                        }

                        keyCacheManager.cacheKey(
                            alias,
                            CachedKeystoreKey(publicKey, algorithm),
                            keystoreName,
                            path,
                        )
                        KeystoreKey(keyAlias = alias, keyPassword = "", keyAlgorithm = algorithm)
                    }

                    Outcome.Success(keys.orEmpty())
                } else {
                    Outcome.Error("Error get keystore aliases", KeystoreFailure.GetAliasesFailure)
                }
            }
        }

    override suspend fun getKeystoreKey(
        keystorePath: String,
        keystoreName: String,
        alias: String
    ): KeystoreKey =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                val key = keyCacheManager.getKey(alias, keystoreName, keystorePath)
                KeystoreKey(
                    keyAlias = alias,
                    keyPassword = "",
                    keyAlgorithm = key?.algorithm ?: KeystoreKeyAlgorithm.UNKNOWN,
                )
            }
        }

    override suspend fun updateKeystore(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
        newKeyAlias: String?,
        newKeyPassword: String?,
        newKeyAlgo: KeystoreKeyAlgorithm?
    ): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        KLogger.d {
            "updateKeystore: $keystorePath, name: $keystoreName, key: $newKeyAlias"
        }
        if (newKeyAlias?.isNotEmpty() == true) {
            val isAdded = keyStoreClient.addKeystoreKey(
                keystore = Keystore(
                    path = keystorePath,
                    name = keystoreName,
                    password = keystorePassword,
                ),
                keyAlias = newKeyAlias,
                keyPassword = newKeyPassword!!,
                // The caller's choice, which this used to accept and then discard: every key added
                // to an existing keystore came out RSA no matter what the screen offered. AES is
                // the fallback-free default only when nothing was chosen at all.
                algorithm = newKeyAlgo ?: KeystoreKeyAlgorithm.RSA,
            )
            if (isAdded.isSuccess) {
                Outcome.Success(Unit)
            } else {
                val exception = isAdded.exceptionOrNull()
                Outcome.Error(exception?.message ?: "Error adding key", KeystoreFailure.KeyGenerationFailure)
            }
        } else {
            Outcome.Error("Error adding key", KeystoreFailure.KeyGenerationFailure)
        }
    }

    override suspend fun deleteKeystore(path: String, name: String, password: String): Boolean = withContext(coroutinesContextFacade.io) {
        keyStoreClient.deleteKeystore(Keystore(path, name, password))
    }

    override suspend fun deleteKeystoreKey(path: String, name: String, password: String, keyAlias: String): Boolean =
        withContext(coroutinesContextFacade.io) {
            keyStoreClient.deleteKeyStoreKey(Keystore(path, name, password), keyAlias)
        }

    private fun unwrapPrivateKey(
        keyCacheManager: KeyCacheManager,
        keyAlias: String,
        keyPassword: String,
    ): Outcome<Key> {
        val keyStore = keyCacheManager.keyStore
            ?: return Outcome.Error("Keystore not loaded", KeystoreFailure.NotFound)

        val unwrapped = keyStoreClient.unwrapKey(keyStore, keyAlias, keyPassword.toCharArray())
            ?: return Outcome.Error("Incorrect key password for '$keyAlias'", KeystoreFailure.KeyNotFound)

        return Outcome.Success(unwrapped)
    }

    private fun encryptionKey(
        keyCacheManager: KeyCacheManager,
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
    ): Outcome<Key> {
        val cached = keyCacheManager.getKey(keyAlias, keystoreName, keystorePath)
            ?: return Outcome.Error("Could not find key", KeystoreFailure.KeyNotFound)

        return cached.publicKey?.let { Outcome.Success(it) }
            ?: unwrapPrivateKey(keyCacheManager, keyAlias, keyPassword)
    }

    override suspend fun encryptText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        plainData: String,
    ): Outcome<EncryptedData> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val key = encryptionKey(keyCacheManager, keystorePath, keystoreName, keyAlias, keyPassword)) {
                    is Outcome.Success -> keyStoreClient.encryptData(key.value, plainData, cipherSalt.encodeToByteArray())
                    is Outcome.Error -> key
                }
            }
        }

    override suspend fun encryptFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        filePath: String,
    ): Outcome<EncryptedData> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val key = encryptionKey(keyCacheManager, keystorePath, keystoreName, keyAlias, keyPassword)) {
                    is Outcome.Success -> {
                        val newFile = createNewFileWithAppendedName(filePath, "encrypted")
                        keyStoreClient.encryptFile(filePath, newFile.absolutePath, key.value, cipherSalt.encodeToByteArray())
                    }
                    is Outcome.Error -> key
                }
            }
        }

    override suspend fun decryptText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        cipherData: String
    ): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val r = unwrapPrivateKey(keyCacheManager, keyAlias, keyPassword)) {
                    is Outcome.Success -> keyStoreClient.decryptData(r.value, cipherData, cipherSalt)
                    is Outcome.Error -> r
                }
            }
        }

    override suspend fun decryptFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        keyPassword: String,
        cipherSalt: String,
        filePath: String
    ): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val r = unwrapPrivateKey(keyCacheManager, keyAlias, keyPassword)) {
                    is Outcome.Success -> {
                        val newFile = createNewFileWithAppendedName(filePath, "decrypted")
                        keyStoreClient.decryptFile(r.value, cipherFilePath = filePath, newFile.absolutePath, cipherSalt, keyPassword)
                    }
                    is Outcome.Error -> r
                }
            }
        }

    override suspend fun signText(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        data: String,
        password: String,
    ): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val r = unwrapPrivateKey(keyCacheManager, keyAlias, password)) {
                    is Outcome.Success -> {
                        val signed = keyStoreClient.sign(privateKey = r.value, data, password)
                        Outcome.Success(signed.orEmpty())
                    }
                    is Outcome.Error -> r
                }
            }
        }

    override suspend fun signFile(
        filePath: String,
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        password: String
    ): Outcome<String>  =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                when (val r = unwrapPrivateKey(keyCacheManager, keyAlias, password)) {
                    is Outcome.Success -> {
                        val signed = keyStoreClient.signFile(filePath, privateKey = r.value, password)
                        Outcome.Success(signed.orEmpty())
                    }
                    is Outcome.Error -> r
                }
            }
        }

    override suspend fun verifySignature(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        data: String,
        signature: String,
    ): Outcome<Boolean> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                keyCacheManager.getKey(keyAlias, keystoreName, keystorePath)?.publicKey?.let { publicKey ->
                    val result = keyStoreClient.verify(publicKey, data = data.encodeToByteArray(), signature = signature)
                    Outcome.Success(result)
                } ?: Outcome.Error("Could not find key", KeystoreFailure.KeyNotFound)
            }
        }

    override suspend fun verifySignatureFile(
        keystorePath: String,
        keystoreName: String,
        keyAlias: String,
        dataPath: String,
        signature: String
    ): Outcome<Boolean> =
        withContext(coroutinesContextFacade.io) {
            keystoreCacheScope(keystoreSession) { scope ->
                val keyCacheManager: KeyCacheManager = scope.get(named(KEYSTORE_CACHE))
                keyCacheManager.getKey(keyAlias, keystoreName, keystorePath)?.publicKey?.let { publicKey ->
                    val dataFile = File(dataPath)
                    Outcome.Success(keyStoreClient.verify(publicKey, dataFile.readBytes(), signature))
                } ?: Outcome.Error("Could not find key", KeystoreFailure.KeyNotFound)
            }
        }

    override suspend fun getPublicKeyBytes(): ByteArray =
        withContext(coroutinesContextFacade.io) {
            passmanSessionScope(userPreferences.getSessionId()) { scope ->
                val publicKey: Key = scope.get(named("encryptionKey"))
                publicKey.encoded
            }
        }

    override suspend fun transferKeystores(device: TrustedDevice): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val keysDir = File("$keystoreDir${user.userName}")
            if (!keysDir.isDirectory || keysDir.listFiles()?.isEmpty() != false) {
                return@withContext Outcome.Error("no keystores to transfer", KeystoreFailure.GetAliasesFailure)
            }
            // Never ship the user's primary login keystore - it carries the RSA keypair the
            // device's password DB is encrypted with. Replacing it on the peer would corrupt
            // the peer's existing data.
            val excluded = DirectoryBundler.syncExclusions(user.userName)
            val bundleBytes = DirectoryBundler.bundle(keysDir, excludeBaseNames = excluded)
            val fileName = "${user.userName.hashCode()}_keystore"
            keystoreTransferService.transferKeystoreBundle(bundleBytes, fileName, device)
        }.getOrElse {
            KLogger.e(it) { "failed to transfer keystores" }
            Outcome.Error("failed to transfer keystores: ${it.message}", TransferFailure.GeneralTransferFailure)
        }
    }

    override suspend fun pushKeystores(device: TrustedDevice): Outcome<Unit> = transferKeystores(device)

    override suspend fun pullKeystores(device: TrustedDevice): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        when (val pullOutcome = keystoreTransferService.pullKeystoreBundle(device = device)) {
            is Outcome.Error -> pullOutcome
            is Outcome.Success -> {
                // The transfer service already decrypted the (post-quantum) response.
                val bundle = pullOutcome.value
                if (bundle.isEmpty()) {
                    return@withContext Outcome.Success(Unit)
                }
                val unbundleResult = runCatching {
                    val user = userPreferences.getUser() as AppUser.LoggedIn
                    val destDir = File("$keystoreDir${user.userName}")
                    // Belt-and-suspenders: even if peer sent the primary login
                    // keystore, do not overwrite our own.
                    val excluded = DirectoryBundler.syncExclusions(user.userName)
                    DirectoryBundler.unbundle(bundle, destDir, excludeBaseNames = excluded)
                }.onFailure {
                    if (it is CancellationException) throw it
                    KLogger.e(it) { "keystore sync pull unbundle failed" }
                }
                if (unbundleResult.isFailure) {
                    Outcome.Error("failed to apply keystore sync pull", KeystoreFailure.GetAliasesFailure)
                } else {
                    Outcome.Success(Unit)
                }
            }
        }
    }

    override fun clearKeyStore() {
        val sessionId = keystoreSession
        if (sessionId.isNotEmpty()) {
            KoinPlatform.getKoin().getScopeOrNull("session-$sessionId")
                ?.getOrNull<KeyCacheManager>(named(KEYSTORE_CACHE))
                ?.clear()
            closeKeystoreCacheScope(sessionId)
        }
        keystoreSession = ""
    }
}
