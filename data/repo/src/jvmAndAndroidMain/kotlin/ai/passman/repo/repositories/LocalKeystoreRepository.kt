package ai.passman.repo.repositories

import ai.passman.crypto.Crypto
import ai.passman.crypto.CryptoKey
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.crypto.io.ArtifactDirectoryLock
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

    /**
     * Run [block] holding `keystore/<userName>/`'s artifact-directory lock.
     *
     * Only the two paths that write the directory without going through [KeystoreClient] need this
     * — [importKeystoreFile] here, and nothing else. Every other write in this class delegates to
     * `JvmKeyStoreClient`, which takes the same lock itself, so wrapping again here would only nest
     * (harmlessly, since the lock is reentrant) and would put the exclusion in two places.
     */
    private fun <T> inKeystoreDirectory(userName: String, block: () -> T): T =
        ArtifactDirectoryLock.withLock(File("$keystoreDir$userName"), block)

    /**
     * Why a keystore may not be written at [destination], or null if it may.
     *
     * Two refusals, both resolved by the **filesystem** rather than compared as strings, because
     * every bypass of a name-level check found so far came from a name that was really a path.
     *
     * 1. **It must be a direct child of the account's own keystore directory.** A requested name is
     *    concatenated into a path (`File(folder, keystoreName)`), so `../bob/bob` was a keystore name
     *    that resolved into *another account's* directory and truncated `bob.pfx` — one user
     *    destroying another's RSA identity from the new-keystore form, while holding only their own
     *    directory's lock.
     * 2. **It must not be the account's identity store.** That file holds the RSA key the vault is
     *    sealed under and nothing else has a copy.
     *
     * `canonicalFile` is what makes both checks real. It normalises `..`, and on the filesystems this
     * ships on it resolves an existing file to its on-disk spelling — so `ALICE.pfx` and an NFD
     * spelling of `café.pfx` both canonicalise onto the identity store they would overwrite, which a
     * string comparison could not see. An earlier version of this guard compared names and folded
     * only case; it was bypassable by Unicode normal form on APFS, which is the default macOS
     * filesystem and the one the desktop app ships against.
     *
     * The identity store existing is what lets its spelling be resolved, and that is exactly the case
     * worth guarding: if it does not exist there is nothing to destroy.
     */
    private fun keystoreDestinationRefusal(destination: File, userName: String): String? {
        val directory = File("$keystoreDir$userName")
        val root = canonicalOf(directory)
        val target = canonicalOf(destination)
        if (target.parentFile != root) {
            return "a keystore name may not contain a path; use a plain name"
        }
        // A name that survives only as the extension. `""` and `"/"` both reduce to the hidden file
        // `.pfx`, which is a direct child and is not the identity store, so both checks below would
        // pass it — and `getAllKeystores` would list a keystore whose name is nothing at all.
        //
        // Matched exactly rather than by trimming. The first attempt stripped dots and spaces before
        // testing for empty, which also refused `"..."` — a name that produces `....pfx`, an odd but
        // perfectly valid file the user is entitled to create. A guard that refuses legitimate input
        // is a worse bug than the cosmetic one it was closing.
        if (target.name.equals(".pfx", ignoreCase = true)) {
            return "a keystore needs a name"
        }
        // Refused here rather than by the filesystem, which only complains after the RSA keygen has
        // already run and then reports a generic create failure.
        if (target.name.toByteArray().size > MAX_FILE_NAME_BYTES) {
            return "that name is too long"
        }
        val identity = KeystoreClient.identityStoreName(userName)
        if (target == canonicalOf(File(directory, identity))) {
            return "that name is reserved for your account's identity; choose another"
        }
        // Belt and braces on top of the resolution above, matching how `unbundle` normalises an
        // inbound entry name. Windows folds `alice.pfx.` and `alice.pfx ` onto `alice.pfx`, and
        // whether canonicalisation reflects that is the platform's business, not something worth
        // depending on for the one file whose loss cannot be recovered. The comparison is
        // case-insensitive for the same reason it is in `unbundle`.
        if (target.name.trimEnd('.', ' ').equals(identity, ignoreCase = true)) {
            return "that name is reserved for your account's identity; choose another"
        }
        return null
    }

    /** Filesystems typically stop at 255 bytes; the margin covers the ones that do not. */
    private val MAX_FILE_NAME_BYTES = 200

    /** Absolute is the fallback, never the raw path: a relative one resolves against the CWD. */
    private fun canonicalOf(file: File): File =
        runCatching { file.canonicalFile }.getOrElse { file.absoluteFile }

    override suspend fun createKeyStore(request: CreateKeyStore.CreateRequest): Outcome<KeyStoreInfo> =
        withContext(coroutinesContextFacade.io) {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            // keystoreDir already ends in a separator; appending another used to produce a
            // double-separator path that only worked because java.io.File normalizes it.
            val keystorePath = "$keystoreDir${user.userName}"
            // The returned name must carry the extension: getAllKeystores lists file names WITH
            // it, and callers compare the two.
            // Blank covers Unicode whitespace too, which `.pfx`-matching alone would let through as a
            // keystore whose name is an em space.
            if (request.keystoreName.isBlank()) {
                return@withContext Outcome.Error("a keystore needs a name", KeystoreFailure.CreateKeystore)
            }
            val fileName =
                if (request.keystoreName.endsWith(".pfx")) request.keystoreName else "${request.keystoreName}.pfx"
            // Resolved and refused before anything is generated or written - see
            // keystoreDestinationRefusal. Ordering the overwrite with a lock would not make it
            // survivable; the write simply must not happen.
            keystoreDestinationRefusal(File(keystorePath, fileName), user.userName)?.let { refusal ->
                KLogger.e { "refusing to create keystore \"${request.keystoreName}\": $refusal" }
                return@withContext Outcome.Error(refusal, KeystoreFailure.CreateKeystore)
            }
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

            // Import keeps the source's own filename, so a file that happens to be called
            // `<user>.pfx` lands on the account's identity store and REPLACE_EXISTING destroys it.
            // Same refusal as createKeyStore, and for the same reason: the identity store is not a
            // keystore the user may replace by hand.
            keystoreDestinationRefusal(destination.toFile(), user.userName)?.let { refusal ->
                KLogger.e { "refusing to import \"${source.fileName}\": $refusal" }
                return@runCatching Outcome.Error(refusal, KeystoreFailure.CreateKeystore)
            }

            // Only the write is locked. Everything above inspected the SOURCE path, which is outside
            // the artifact directory, so there is no read here to keep atomic with it.
            inKeystoreDirectory(user.userName) {
                // The per-user dir otherwise only exists once a keystore has been saved; importing
                // into a fresh account must not depend on that.
                destination.parent?.let { Files.createDirectories(it) }
                Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING)
            }

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

    // Both deletes report failure as `false` rather than by throwing, and both now go through the
    // artifact-directory lock, which CAN throw when the directory is busy. Neither caller is prepared
    // for that: `KeystoreDetailsViewModel.onDeleteKeystoreClicked` calls straight into
    // `viewModelScope.launch` with no runCatching, so an escaping exception is a crash where the
    // contract promised a `false` the screen already knows how to show. Translated here rather than
    // at each caller, since "could not get the lock" means exactly what `false` means: nothing was
    // deleted, try again.
    override suspend fun deleteKeystore(path: String, name: String, password: String): Boolean = withContext(coroutinesContextFacade.io) {
        runCatching { keyStoreClient.deleteKeystore(Keystore(path, name, password)) }
            .getOrElse { failure ->
                if (failure is CancellationException) throw failure
                KLogger.e(failure) { "failed to delete keystore $name" }
                false
            }
    }

    override suspend fun deleteKeystoreKey(path: String, name: String, password: String, keyAlias: String): Boolean =
        withContext(coroutinesContextFacade.io) {
            runCatching { keyStoreClient.deleteKeyStoreKey(Keystore(path, name, password), keyAlias) }
                .getOrElse { failure ->
                    if (failure is CancellationException) throw failure
                    KLogger.e(failure) { "failed to delete key $keyAlias from $name" }
                    false
                }
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
