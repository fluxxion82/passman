package ai.passman.keystore

import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.crypto.io.DurableFiles
import ai.passman.crypto.vault.IdentityStorePassword
import ai.passman.keystore.model.Keystore
import ai.passman.logging.KLogger
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.crypto.exception.CryptoFailure
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.exception.KeystoreFailure
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKey
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.user.exception.AuthFailure
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.MGF1ParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.bc.BcX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

private const val KEY_YEARS_VALID = 30
private val KEYSTORE_ENVELOPE_MAGIC = byteArrayOf('P'.code.toByte(), 'M'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte())
private const val KEYSTORE_ENVELOPE_VERSION: Byte = 1
private const val RSA_ENVELOPE_KEY_TYPE: Byte = 1
private const val AES_ENVELOPE_KEY_TYPE: Byte = 2
private const val GCM_NONCE_LENGTH = 12
private const val GCM_TAG_LENGTH_BITS = 128
private const val RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"

class JvmKeyStoreClient : KeystoreClient {

    init {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    /**
     * Run [block] holding [keystorePath]'s artifact-directory lock.
     *
     * `keystore/<user>/` is a directory sync unbundles into, and `unbundle` preserves the file it is
     * about to replace by renaming it away and then renaming the inbound version in. Every write
     * this class makes has to be ordered against those two steps, or a keystore published in between
     * is overwritten having never been preserved.
     *
     * The read-modify-write methods take it around the **load as well as the store**. Reading the
     * store, editing the in-memory copy and writing it back is only correct if nothing else replaces
     * the file in between; a lock around the write alone would let a sync land in the middle and
     * then be silently reverted by a `store()` built from the pre-sync bytes. That is why
     * [addKeystoreKey] and [deleteKeyStoreKey] hold this across their key generation too — the cost
     * is a keygen inside the lock, and the alternative is a lost write.
     *
     * ## Ordering
     *
     * **This lock is the outer one.** [commitIdentityStore] and [restoreIdentityKeyStoreFromBackup]
     * take it and then take [IdentityStoreLock]; nothing here may acquire it while already holding
     * [IdentityStoreLock].
     *
     * Both are needed on those two paths because the two locks are **not** disjoint. The sync
     * exclusion list was believed to keep `<user>.pfx` out of every bundle, which would have meant
     * `unbundle` could never touch it — but that list compares basename strings while the filesystem
     * resolves paths, and `IdentityStoreDisplaceableTest` shows three ways they disagree on the
     * identity store's own name. A user-added keystore named after the account lands on it too.
     *
     * The order is this-then-[IdentityStoreLock] because [IdentityStoreLock] is bounded, fails
     * rather than waits, and holds a cross-process `FileLock`. Nested the other way, a writer would
     * block for this lock's whole budget while holding that one — the wedge [IdentityStoreLock]
     * documents as unacceptable.
     */
    private fun <T> inArtifactDirectory(keystorePath: String, block: () -> T): T =
        ArtifactDirectoryLock.withLock(File(keystorePath), block)

    private fun pkcs12KeyStore(): KeyStore {
        val provider = Security.getProvider("SUN") ?: Security.getProvider("SunJSSE")
        val ks = if (provider != null) {
            KeyStore.getInstance(KeyStoreType.PKCS12.type, provider)
        } else {
            KeyStore.getInstance(KeyStoreType.PKCS12.type)
        }
        KLogger.d { "pkcs12 provider: ${ks.provider.name}" }
        return ks
    }

    private fun loadPkcs12(file: File, password: CharArray): KeyStore {
        val sunProvider = Security.getProvider("SUN") ?: Security.getProvider("SunJSSE")
        if (sunProvider != null) {
            try {
                return withBouncyCastleDemoted {
                    val ks = KeyStore.getInstance(KeyStoreType.PKCS12.type, sunProvider)
                    file.inputStream().use { ks.load(it, password) }
                    KLogger.d { "pkcs12 loaded via ${ks.provider.name}" }
                    ks
                }
            } catch (e: Exception) {
                KLogger.w(e) {
                    "pkcs12 load via ${sunProvider.name} failed (${e.javaClass.simpleName}: ${e.message}); falling back to BouncyCastle"
                }
            }
        }
        val bcKs = KeyStore.getInstance(KeyStoreType.PKCS12.type, BouncyCastleProvider.PROVIDER_NAME)
        file.inputStream().use { bcKs.load(it, password) }
        KLogger.d { "pkcs12 loaded via ${bcKs.provider.name}" }
        return bcKs
    }

    /**
     * Mutations on a SUN-loaded PKCS12 keystore (setKeyEntry, deleteEntry, store) internally
     * resolve `Cipher.getInstance("<PBE_ALGO>")` via the active JCE provider list. With BC at
     * position 1, BC's PBE wins and the resulting key bag is encrypted in BC's format — which
     * SUN cannot later decrypt during `getKey`, producing "Given final block not properly padded".
     *
     * For BC-loaded keystores, demoting BC would break the operation entirely (no BC PBE
     * implementation available). So only demote when the keystore is SUN-flavored.
     */
    private inline fun <T> withProviderMatching(keyStore: KeyStore, block: () -> T): T {
        val needsDemote = keyStore.provider.name == "SUN" || keyStore.provider.name == "SunJSSE"
        return if (needsDemote) withBouncyCastleDemoted(block) else block()
    }

    private inline fun <T> withBouncyCastleDemoted(block: () -> T): T {
        val bcWasPresent = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null
        if (bcWasPresent) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        }
        try {
            return block()
        } finally {
            if (bcWasPresent && Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }
    }

    override fun createKeyStore(
        keystoreType: KeyStoreType,
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
        initialKey: KeystoreKey?,
    ): Result<Keystore> {
        return runCatching {
            val keyStore = KeyStore.getInstance(keystoreType.type) // JKS, PKCS12, BKS, AndroidKeyStore
            keyStore.load(null, keystorePassword.toCharArray())

            // Before the store ever touches disk, so a keygen failure leaves no empty store file
            // behind — and the whole creation is one store() rather than store/load/store.
            if (initialKey != null) {
                withProviderMatching(keyStore) {
                    when (initialKey.keyAlgorithm) {
                        KeystoreKeyAlgorithm.RSA -> {
                            val keyPair = KeyService.createRSAKeys()
                            keyStore.setKeyEntry(
                                initialKey.keyAlias,
                                keyPair.private,
                                initialKey.keyPassword.toCharArray(),
                                arrayOf<Certificate>(createRootCertificate(keyPair)),
                            )
                        }

                        KeystoreKeyAlgorithm.AES -> keyStore.setKeyEntry(
                            initialKey.keyAlias,
                            KeyService.createAESKey(),
                            initialKey.keyPassword.toCharArray(),
                            null,
                        )

                        KeystoreKeyAlgorithm.UNKNOWN -> error("unknown keystore key algorithm")
                    }
                }
            }

            KLogger.d { "external file path: $keystorePath" }
            // Only the disk half is locked. Everything above built the store in memory and read
            // nothing from this directory, so holding the lock across the key generation would make
            // an inbound sync wait on an RSA keygen for no gain. The read-modify-write methods
            // cannot do this - see inArtifactDirectory.
            inArtifactDirectory(keystorePath) {
                val folder = File(keystorePath)
                if (!folder.exists()) {
                    KLogger.d { "folder dne" }
                    folder.mkdirs()
                }

                val external = File(folder.path, keystoreName)
                KLogger.d { "external file: $external" }
                if (!external.exists()) {
                    KLogger.d { "file dne" }
                    external.createNewFile()
                }

                keyStore.store(external.outputStream(), keystorePassword.toCharArray())
            }

            KLogger.d {
                "new keystore $keystoreName at location: $keystorePath " +
                    "with aliases: ${keyStore.aliases().toList()}"
            }

            Keystore(
                path = keystorePath,
                name = keystoreName,
                password = keystorePassword,
            )
        }.onFailure {
            KLogger.e(it) { "new default keystore: ${it.message}" }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun encryptData(publicKey: Key, plainData: String, cipherIv: ByteArray): Outcome<EncryptedData> {
        return runCatching {
            val encrypted = encryptVersioned(publicKey, plainData.encodeToByteArray(), cipherIv)
            Outcome.Success(EncryptedData(Base64.encode(encrypted.bytes), Base64.encode(encrypted.nonce)))
        }.getOrElse {
            KLogger.e(it) { "failed to init cipher" }
            Outcome.Error(
                "Failed to init cipher for encryption",
                CryptoFailure.CipherInitFailure("Exception init cipher: ${it.message}")
            )
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun encryptFile(filePath: String, newFilePath: String, publicKey: Key, cipherIv: ByteArray): Outcome<EncryptedData> {
        return runCatching {
            val encrypted = encryptVersioned(publicKey, File(filePath).readBytes(), cipherIv)
            FileOutputStream(File(newFilePath)).use { it.write(encrypted.bytes) }
            Outcome.Success(EncryptedData(newFilePath, Base64.encode(encrypted.nonce)))
        }.getOrElse {
            KLogger.e(it) { "failed to init cipher" }
            Outcome.Error(
                "Failed to init cipher for encryption",
                CryptoFailure.CipherInitFailure("Exception init cipher: ${it.message}")
            )
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun decryptData(secretKey: Key, cipherData: String, cipherIv: String): Outcome<String> {
        return runCatching {
            val decoded = Base64.decode(cipherData)
            val decrypt = decryptPayload(secretKey, decoded, cipherIv.encodeToByteArray())
            Outcome.Success(String(decrypt))
        }.getOrElse {
            KLogger.e(it) { "failed to init cipher for decryption" }
            Outcome.Error(
                "Failed to init cipher for decryption",
                CryptoFailure.CipherInitFailure("Exception init cipher: ${it.message}")
            )
        }
    }

    override fun decryptFile(secretKey: Key, cipherFilePath: String, decryptedFilePath: String, cipherIv: String, keyPassword: String): Outcome<String> {
        return runCatching {
            KLogger.i { "cipherData:" }
            val decrypted = decryptPayload(secretKey, File(cipherFilePath).readBytes(), cipherIv.encodeToByteArray())
            FileOutputStream(File(decryptedFilePath)).use { it.write(decrypted) }
            Outcome.Success(decryptedFilePath)
        }.getOrElse {
            KLogger.e(it) { "failed to init cipher for decryption" }

            Outcome.Error(
                "Failed to init cipher for decryption",
                CryptoFailure.CipherInitFailure("Exception init cipher: ${it.message}")
            )
        }
    }

    private fun encryptVersioned(key: Key, plaintext: ByteArray, aad: ByteArray): VersionedCiphertext {
        val keyType = keyType(key)
        val contentKey = if (keyType == RSA_ENVELOPE_KEY_TYPE) newAesKey() else key as? SecretKey
            ?: throw IllegalArgumentException("AES encryption requires a secret key")
        val wrappedKey = if (keyType == RSA_ENVELOPE_KEY_TYPE) wrapContentKey(key, contentKey) else ByteArray(0)
        require(wrappedKey.size <= 0xffff) { "Wrapped key is too large" }
        val nonce = ByteArray(GCM_NONCE_LENGTH).also(SecureRandom()::nextBytes)
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, contentKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
        cipher.updateAAD(aad)
        val ciphertext = cipher.doFinal(plaintext)
        val envelope = ByteArrayOutputStream().apply {
            write(KEYSTORE_ENVELOPE_MAGIC)
            write(KEYSTORE_ENVELOPE_VERSION.toInt())
            write(keyType.toInt())
            write(wrappedKey.size ushr 8)
            write(wrappedKey.size and 0xff)
            write(wrappedKey)
            write(nonce)
            write(ciphertext)
        }.toByteArray()
        return VersionedCiphertext(envelope, nonce)
    }

    private fun decryptPayload(key: Key, ciphertext: ByteArray, aad: ByteArray): ByteArray =
        if (isVersioned(ciphertext)) decryptVersioned(key, ciphertext, aad) else decryptLegacy(key, ciphertext, aad)

    private fun decryptVersioned(key: Key, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val envelope = parseEnvelope(ciphertext)
        val expectedType = keyType(key)
        require(envelope.keyType == expectedType) { "Encrypted payload key type does not match supplied key" }
        val contentKey = if (envelope.keyType == RSA_ENVELOPE_KEY_TYPE) {
            unwrapContentKey(key, envelope.wrappedKey)
        } else {
            key as? SecretKey ?: throw IllegalArgumentException("AES decryption requires a secret key")
        }
        val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, contentKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, envelope.nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(envelope.ciphertext)
    }

    private fun decryptLegacy(key: Key, ciphertext: ByteArray, cipherIv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(key.algorithm, "BC")
        if (cipherIv.isNotEmpty()) {
            cipher.init(Cipher.DECRYPT_MODE, key, javax.crypto.spec.IvParameterSpec(cipherIv))
        } else {
            cipher.init(Cipher.DECRYPT_MODE, key)
        }
        return cipher.doFinal(ciphertext)
    }

    private fun newAesKey(): SecretKey = KeyGenerator.getInstance("AES").apply {
        init(256, SecureRandom())
    }.generateKey()

    private fun wrapContentKey(key: Key, contentKey: SecretKey): ByteArray = rsaCipher(Cipher.ENCRYPT_MODE, key).doFinal(contentKey.encoded)

    private fun unwrapContentKey(key: Key, wrappedKey: ByteArray): SecretKey =
        SecretKeySpec(rsaCipher(Cipher.DECRYPT_MODE, key).doFinal(wrappedKey), "AES")

    private fun rsaCipher(mode: Int, key: Key): Cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION, "BC").apply {
        init(
            mode,
            key,
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT),
        )
    }

    private fun keyType(key: Key): Byte = when (key.algorithm.uppercase(Locale.ROOT)) {
        "RSA" -> RSA_ENVELOPE_KEY_TYPE
        "AES" -> AES_ENVELOPE_KEY_TYPE
        else -> throw IllegalArgumentException("Unsupported encryption key algorithm: ${key.algorithm}")
    }

    private fun isVersioned(ciphertext: ByteArray): Boolean =
        ciphertext.size >= KEYSTORE_ENVELOPE_MAGIC.size && ciphertext.copyOfRange(0, KEYSTORE_ENVELOPE_MAGIC.size).contentEquals(KEYSTORE_ENVELOPE_MAGIC)

    private fun parseEnvelope(ciphertext: ByteArray): KeystoreEnvelope {
        var offset = KEYSTORE_ENVELOPE_MAGIC.size
        fun read(count: Int): ByteArray {
            require(count >= 0 && ciphertext.size - offset >= count) { "Truncated encrypted payload" }
            return ciphertext.copyOfRange(offset, offset + count).also { offset += count }
        }

        val version = read(1)[0]
        require(version == KEYSTORE_ENVELOPE_VERSION) { "Unsupported encrypted payload version: $version" }
        val keyType = read(1)[0]
        require(keyType == RSA_ENVELOPE_KEY_TYPE || keyType == AES_ENVELOPE_KEY_TYPE) { "Unsupported encrypted payload key type" }
        val wrappedKeyLengthBytes = read(2)
        val wrappedKeyLength = ((wrappedKeyLengthBytes[0].toInt() and 0xff) shl 8) or (wrappedKeyLengthBytes[1].toInt() and 0xff)
        val wrappedKey = read(wrappedKeyLength)
        if (keyType == RSA_ENVELOPE_KEY_TYPE) require(wrappedKey.isNotEmpty()) { "RSA encrypted payload has no wrapped key" }
        if (keyType == AES_ENVELOPE_KEY_TYPE) require(wrappedKey.isEmpty()) { "AES encrypted payload has a wrapped key" }
        val nonce = read(GCM_NONCE_LENGTH)
        val body = read(ciphertext.size - offset)
        require(body.size >= GCM_TAG_LENGTH_BITS / 8) { "Truncated GCM ciphertext" }
        return KeystoreEnvelope(keyType, wrappedKey, nonce, body)
    }

    private data class VersionedCiphertext(val bytes: ByteArray, val nonce: ByteArray)

    private data class KeystoreEnvelope(
        val keyType: Byte,
        val wrappedKey: ByteArray,
        val nonce: ByteArray,
        val ciphertext: ByteArray,
    )

    override fun getKeyStoreInfo(keystore: Keystore): Result<KeyStore> {
        return runCatching {
            KLogger.d { "external file path: ${keystore.path}" }
            val external = File(keystore.path, keystore.name)
            KLogger.d { "external file: $external" }
            if (!external.exists()) {
                KLogger.d { "file dne" }
                throw IllegalStateException("file dne")
            }

            val keyStore = loadPkcs12(external, keystore.password.toCharArray())

            keyStore.aliases().toList().forEach {
                KLogger.d { "alias: $it" }
            }

            KLogger.d { "loaded keystore ${external.name} at location: ${external.path}" }

            keyStore
        }.onFailure {
            KLogger.i { "new default keystore: ${it.message}" }
        }
    }

    /**
     * Load, edit and store under one lock — see [inArtifactDirectory] for why the load is inside it.
     *
     * The lock is taken **inside** the `runCatching`, not around it. This method reports failure as a
     * `Result`, and the lock can refuse when the directory is busy; taken outside, that refusal would
     * be thrown at callers who are only prepared for a failed `Result` —
     * `LocalKeystoreRepository.updateKeystore` does not catch, and `AddKeystoreKeyViewModel` calls it
     * from a bare `viewModelScope.launch`. A sync holding the lock past its budget would then be a
     * crash on the Add Key button instead of the error the contract promises.
     */
    override fun addKeystoreKey(keystore: Keystore, keyAlias: String, keyPassword: String, algorithm: KeystoreKeyAlgorithm): Result<Boolean> =
        runCatching {
            inArtifactDirectory(keystore.path) {
                addKeystoreKeyLocked(keystore, keyAlias, keyPassword, algorithm).getOrThrow()
            }
        }

    private fun addKeystoreKeyLocked(keystore: Keystore, keyAlias: String, keyPassword: String, algorithm: KeystoreKeyAlgorithm): Result<Boolean> {
        return runCatching {
            loadKeyStoreFromPath(
                keystorePath = keystore.path,
                keystoreName = keystore.name,
                keystorePassword = keystore.password,
            )?.let { kStore ->
                withProviderMatching(kStore) {
                    when (algorithm) {
                        KeystoreKeyAlgorithm.RSA -> {
                            val keyPair = KeyService.createRSAKeys()
                            val certificate = createRootCertificate(keyPair)

                            val certChain = arrayOfNulls<Certificate>(1)
                            certChain[0] = certificate
                            kStore.setKeyEntry(
                                keyAlias,
                                keyPair.private,
                                keyPassword.toCharArray(),
                                certChain
                            )
                        }

                        KeystoreKeyAlgorithm.AES -> {
                            val encryptionKey = KeyService.createAESKey()
                            kStore.setKeyEntry(
                                keyAlias,
                                encryptionKey,
                                keyPassword.toCharArray(),
                                null,
                            )
                        }

                        KeystoreKeyAlgorithm.UNKNOWN -> error("unknown keystore key algorithm")
                    }

                    FileOutputStream(File(keystore.path, keystore.name)).use { fos ->
                        kStore.store(fos, keystore.password.toCharArray())
                    }
                }
                true
            } ?: false
        }.onFailure {
            KLogger.i { "new default keystore: ${it.message}" }
        }
    }

    override fun deleteKeystore(keystore: Keystore): Boolean =
        inArtifactDirectory(keystore.path) { File(keystore.path, keystore.name).delete() }

    /** Load, edit and store under one lock — see [inArtifactDirectory] for why the load is inside it. */
    override fun deleteKeyStoreKey(
        keystore: Keystore,
        keyAlias: String
    ): Boolean = inArtifactDirectory(keystore.path) { deleteKeyStoreKeyLocked(keystore, keyAlias) }

    private fun deleteKeyStoreKeyLocked(
        keystore: Keystore,
        keyAlias: String
    ): Boolean {
        return loadKeyStoreFromPath(
            keystorePath = keystore.path,
            keystoreName = keystore.name,
            keystorePassword = keystore.password
        )?.let { keyStore ->
            withProviderMatching(keyStore) {
                keyStore.aliases().toList().find {
                    it == keyAlias
                }?.let { key ->
                    keyStore.deleteEntry(key)
                }

                FileOutputStream(File(keystore.path, keystore.name)).use { fos ->
                    keyStore.store(fos, keystore.password.toCharArray())
                }
            }
            true
        } ?: false
    }

    /**
     * Load, re-key and publish under one lock — see [inArtifactDirectory] for why the load is inside it.
     *
     * Wrapped so a busy directory becomes the `Outcome.Error` this method already promises rather than
     * a throw, for the same reason as [addKeystoreKey].
     */
    override fun changeKeystorePassword(
        keystorePath: String,
        keystoreName: String,
        keystoreType: KeyStoreType,
        oldPassword: String,
        newPassword: String,
    ): Outcome<Unit> = runCatching {
        inArtifactDirectory(keystorePath) {
            changeKeystorePasswordLocked(keystorePath, keystoreName, keystoreType, oldPassword, newPassword)
        }
    }.getOrElse {
        KLogger.e(it) { "failed to change keystore password: ${it.localizedMessage}" }
        // `Outcome.Error.message` is non-null, and `localizedMessage` is a platform type that really
        // can be null here: an InterruptedException from the lock's interruptible monitor wait or
        // retry sleep carries no message, so passing it straight through would throw an NPE out of
        // the very handler added to stop this method throwing.
        Outcome.Error(it.localizedMessage ?: "change failed", KeystoreFailure.ChangePasswordFailure)
    }

    private fun changeKeystorePasswordLocked(
        keystorePath: String,
        keystoreName: String,
        keystoreType: KeyStoreType,
        oldPassword: String,
        newPassword: String,
    ): Outcome<Unit> {
        return runCatching {
            val oldKeyStoreOutcome = runCatching {
                val ks = loadKeyStoreFromPath(
                    keystorePath = keystorePath,
                    keystoreName = keystoreName,
                    keystorePassword = oldPassword,
                )

                if (ks == null) {
                    Outcome.Error("failed to load keystore", KeystoreFailure.NotFound)
                } else {
                    Outcome.Success(ks)
                }
            }.getOrElse {
                Outcome.Error(it.message ?: "invalid password", AuthFailure.InvalidPassword)
            }

            if (oldKeyStoreOutcome.isSuccessful()) {
                val oldKeyStore = oldKeyStoreOutcome.value

                // NOT `oldKeyStore.load(null, ...)`. That call used to sit here and it is what
                // `KeyStore` does to initialise an *empty* store — it discarded every entry
                // loadKeyStoreFromPath had just read, so the alias loop below copied nothing and this
                // method returned Success having replaced the user's RSA identity with an empty
                // PKCS#12. Silent, unrecoverable, and previously reachable only from an explicit
                // master-password change; the keyring migration runs this on the first login of every
                // pre-existing account, which is how it was finally caught.
                val newKeyStore = KeyStore.getInstance(keystoreType.type, oldKeyStore.provider)
                    .apply { load(null, newPassword.toCharArray()) }

                val folder = File(keystorePath)
                val external = File(folder.path, keystoreName)
                val expectedAliases = oldKeyStore.aliases().toList()

                // Build the replacement beside the original and only swap it in once it has been read
                // back and proved to hold the same entries under the new password. The previous code
                // deleted the .pfx and recreated it in place, so a crash — or, as above, a silently
                // empty result — destroyed the account's only RSA identity. Nothing here touches the
                // original file until the replacement is known good.
                val tmp = File.createTempFile("${external.name}.", ".tmp", folder)
                try {
                    withProviderMatching(oldKeyStore) {
                        expectedAliases.forEach { alias ->
                            newKeyStore.setKeyEntry(
                                alias,
                                oldKeyStore.getKey(alias, oldPassword.toCharArray()),
                                newPassword.toCharArray(),
                                oldKeyStore.getCertificateChain(alias),
                            )
                        }
                        tmp.outputStream().use { out ->
                            newKeyStore.store(out, newPassword.toCharArray())
                            out.flush()
                            out.fd.sync()
                        }
                    }

                    val verification = loadPkcs12(tmp, newPassword.toCharArray())
                    check(verification.aliases().toList().toSet() == expectedAliases.toSet()) {
                        "re-keyed keystore holds ${verification.aliases().toList().size} of " +
                            "${expectedAliases.size} entries"
                    }
                    expectedAliases.forEach { alias ->
                        checkNotNull(unwrapKey(verification, alias, newPassword.toCharArray())) {
                            "re-keyed keystore entry does not unwrap under the new password"
                        }
                    }

                    // Not `renameTo` + delete-then-retry. `File.renameTo` fails when the destination
                    // exists on Windows, so that fallback was the *normal* path there, and between
                    // the delete and the retry the account's only RSA identity exists under neither
                    // name — a crash or a second failed rename loses it outright. This method runs on
                    // the first login of every pre-existing account, so the exposed population was
                    // every existing Windows user, once. DurableFiles.replace never unlinks the
                    // target as a separate step and fsyncs the directory so the swap is durable.
                    DurableFiles.replace(tmp, external)
                } finally {
                    tmp.delete()
                }

                Outcome.Success(Unit)
            } else {
                oldKeyStoreOutcome as Outcome.Error
            }
        }.getOrElse {
            KLogger.e(it) { "failed to change keystore password: ${it.localizedMessage}" }
            Outcome.Error(it.localizedMessage ?: "change failed", KeystoreFailure.ChangePasswordFailure)
        }
    }

    // ---------------------------------------------------------------- identity store
    //
    // The three methods below are the only writers of low-PBE PKCS#12 in the codebase, and they are
    // reached only from `JvmKeystoreLifecycle`, which owns the account `.pfx` and passes the
    // keyring-derived store password. Everything above this line — the keystore-tools paths, where
    // the password is whatever the user typed — keeps the JCA writer and BouncyCastle's defaults.
    // See LowPbePkcs12Writer for why that split is the whole security argument.

    override fun createIdentityKeyStore(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: IdentityStorePassword,
        keyAlias: String,
    ): Outcome<Unit> = runCatching {
        val folder = File(keystorePath)
        val keyPair = KeyService.createRSAKeys()
        val encoded = LowPbePkcs12Writer.encode(
            alias = keyAlias,
            privateKey = keyPair.private,
            chain = listOf(createRootCertificate(keyPair)),
            password = keystorePassword.value.toCharArray(),
        )
        commitIdentityStore(folder, File(folder, keystoreName), encoded, keystorePassword.value, listOf(keyAlias))
        KLogger.d { "identity store created at $keystorePath with alias $keyAlias" }
        Outcome.Success(Unit)
    }.getOrElse {
        KLogger.e(it) { "failed to create the identity store: ${it.message}" }
        Outcome.Error(it.message ?: "failed to create the identity store", KeystoreFailure.CreateKeystore)
    }

    override fun changeIdentityKeyStorePassword(
        keystorePath: String,
        keystoreName: String,
        oldPassword: String,
        newPassword: IdentityStorePassword,
    ): Outcome<Unit> = runCatching {
        val folder = File(keystorePath)
        val external = File(folder, keystoreName)
        if (!external.isFile) {
            return Outcome.Error("failed to load keystore", KeystoreFailure.NotFound)
        }
        // The lock spans the READ as well as the commit. This is a read-modify-write: the bytes
        // published below are derived from the store loaded here, so a sync landing between the two
        // would be silently reverted by the commit — the exact shape [inArtifactDirectory] exists to
        // prevent, and one this method had while `commitIdentityStore` took the lock by itself. It is
        // reentrant, so that inner acquisition just re-enters.
        //
        // The outcome comes back as the lambda's value rather than by an early `return`: the lock
        // takes a plain (non-inline) lambda, so only a labelled return is legal from inside it.
        inArtifactDirectory(keystorePath) {
            // A wrong old password must be an error, not an exception, and must not touch the file —
            // the migration state machine in LocalUserRepository reads this answer to decide what to
            // do next.
            val oldKeyStore = runCatching { loadPkcs12(external, oldPassword.toCharArray()) }.getOrElse {
                return@inArtifactDirectory Outcome.Error(
                    it.message ?: "invalid password",
                    AuthFailure.InvalidPassword,
                )
            }
            val expectedAliases = oldKeyStore.aliases().toList()
            // Straight from the loaded store to the new bytes. There is no intermediate KeyStore
            // holding the entries under the new password, so there is nothing a stray `store()` could
            // write at the provider's own parameters.
            val encoded =
                LowPbePkcs12Writer.encode(oldKeyStore, oldPassword.toCharArray(), newPassword.value.toCharArray())
            commitIdentityStore(folder, external, encoded, newPassword.value, expectedAliases)
            Outcome.Success(Unit)
        }
    }.getOrElse {
        KLogger.e(it) { "failed to change the identity store password: ${it.localizedMessage}" }
        Outcome.Error(it.localizedMessage ?: "change failed", KeystoreFailure.ChangePasswordFailure)
    }

    override fun reencodeIdentityKeyStore(
        keystorePath: String,
        keystoreName: String,
        password: IdentityStorePassword,
    ): Outcome<Unit> = runCatching {
        val folder = File(keystorePath)
        val external = File(folder, keystoreName)
        if (!external.isFile) {
            return Outcome.Error("failed to load keystore", KeystoreFailure.NotFound)
        }
        // The cheap half, and the one that runs on every login after the first: reading the algorithm
        // identifiers out of the file runs no PBE at all. Deliberately outside the lock — it decides
        // only whether there is work to do and touches nothing, and taking the lock to answer "no"
        // would put a lock file in every account directory on every login.
        if (!LowPbePkcs12Writer.hasLegacyPbe(external)) {
            return Outcome.Success(Unit)
        }
        // Read-modify-write from here on, so the lock spans the load as well as the commit — see
        // changeIdentityKeyStorePassword for why, and for why the result is a returned value.
        inArtifactDirectory(keystorePath) {
            val keyStore = runCatching { loadPkcs12(external, password.value.toCharArray()) }.getOrElse {
                return@inArtifactDirectory Outcome.Error(
                    it.message ?: "invalid password",
                    AuthFailure.InvalidPassword,
                )
            }
            val expectedAliases = keyStore.aliases().toList()
            val encoded = LowPbePkcs12Writer.encode(keyStore, password.value.toCharArray())
            commitIdentityStore(folder, external, encoded, password.value, expectedAliases)
            KLogger.d { "identity store re-encoded at low PBE parameters (${expectedAliases.size} entries)" }
            Outcome.Success(Unit)
        }
    }.getOrElse {
        KLogger.e(it) { "failed to re-encode the identity store: ${it.localizedMessage}" }
        Outcome.Error(it.localizedMessage ?: "re-encode failed", KeystoreFailure.ChangePasswordFailure)
    }

    override fun restoreIdentityKeyStoreFromBackup(
        keystorePath: String,
        keystoreName: String,
        password: String,
        expectedAlias: String,
    ): Boolean {
        val folder = File(keystorePath)
        val target = File(folder, keystoreName)
        val backup = File(folder, KeystoreClient.identityStoreBackupName(keystoreName))

        // Asked before the lock is taken, and asked again after it. Out here it is the fast path:
        // `canOpenKeystore` calls this on every failed password probe — which is every ordinary login,
        // since the derived password and the login password are tried in turn — and neither of these
        // two questions needs a lock to answer "no, there is nothing to recover". Taking the lock
        // first would create a lock file in every account directory to establish that.
        if (!backup.isFile) return false
        if (isLiveStoreReadable(target)) return false

        return runCatching {
            // Artifact lock outermost, identity-store lock inside it - see inArtifactDirectory.
            // Taken after the two unlocked fast-path checks above, so an ordinary login that has
            // nothing to recover still answers without creating a lock file in every account.
            inArtifactDirectory(folder.path) {
                IdentityStoreLock.withLock(folder, keystoreName) {
                    // The re-check, and the reason this is inside the lock at all.
                    //
                    // Everything above was read before this call had any exclusion, so by now a commit may
                    // have run to completion: published a new store, verified it, and deleted the backup as
                    // debris. Publishing what was read earlier would put the *pre*-commit store back and
                    // destroy the only copy of the new one — and when the commit was the
                    // login-password→derived-password migration, that is a migration reporting success and
                    // then being silently reverted. A live store that parses is the commit's own success
                    // criterion, so seeing one here means the race was lost and there is nothing to do.
                    if (isLiveStoreReadable(target)) {
                        KLogger.i {
                            "identity store: $keystoreName became readable while this recovery waited for the " +
                                "lock; a commit published it, so ${backup.name} is left untouched"
                        }
                        return@withLock false
                    }
                    // The winner may equally have deleted the backup on its way out.
                    if (!backup.isFile) return@withLock false

                    // The same question the commit asks of its replacement, against the same alias the
                    // caller is about to demand: does it open, is that entry a private key, and does the
                    // key actually come out? A backup that only satisfies the file MAC is not a recovery,
                    // and neither is one holding somebody else's alias — that used to pass here, be
                    // published, and have the backup deleted, after which the caller's probe for
                    // `expectedAlias` failed and the last artefact was gone.
                    val loaded = loadPkcs12(backup, password.toCharArray())
                    val aliases = loaded.aliases().toList()
                    verifyIdentityAlias(loaded, aliases, expectedAlias, password, "the backup")

                    // Published through a temp copy rather than by moving the backup itself: if this fails
                    // half way the backup is still there to try again with, which is the entire reason it
                    // exists. Only once the live store is durably in place does the backup stop being the
                    // last copy.
                    val tmp = File.createTempFile("$keystoreName.", KeystoreClient.IDENTITY_STORE_TEMP_SUFFIX, folder)
                    try {
                        FileOutputStream(tmp).use { out ->
                            backup.inputStream().use { it.copyTo(out) }
                            out.flush()
                            out.fd.sync()
                        }
                        DurableFiles.replace(tmp, target)
                    } finally {
                        tmp.delete()
                    }

                    // Only now is the backup debris — and only if the file that replaced it satisfies the
                    // contract as *published*, read back from its final path rather than assumed from the
                    // bytes that went in.
                    val published = loadPkcs12(target, password.toCharArray())
                    verifyIdentityAlias(published, published.aliases().toList(), expectedAlias, password, "the restored store")
                    backup.delete()
                    KLogger.w {
                        "recovered $keystoreName from ${backup.name}: the previous commit could neither publish " +
                            "its replacement nor put the original back (${aliases.size} entries restored)"
                    }
                    true
                }
            }
        }.getOrElse {
            // Never delete a backup that did not verify. A stale one from an older password is still
            // the only artefact pointing at what happened. The reason is carried in the message
            // because the three cases want different human responses: a busy lock means try again, a
            // wrong password means try the other one, and a missing alias means this backup is not
            // this account's identity.
            KLogger.w(it) { "identity store recovery declined: ${it.message}; ${backup.absolutePath} is kept" }
            false
        }
    }

    /**
     * Whether the file at [target] is a live identity store rather than damage.
     *
     * "Fails to load" has to mean *structurally* unreadable, not "this password does not open it". A
     * store that parses as a PKCS#12 but rejects the password is the ordinary pre-migration answer —
     * login is about to try the other password — and restoring over it would destroy a perfectly good
     * identity on the strength of a wrong guess. The ASN.1 parse needs no password and settles the
     * question.
     */
    private fun isLiveStoreReadable(target: File): Boolean =
        target.isFile && LowPbePkcs12Writer.isStructurallyPkcs12(target)

    /**
     * Prove [store] holds [expectedAlias] as a private-key entry that unwraps under [password].
     *
     * Aliases are matched case-insensitively because the reader decides their case: SUN lowercases
     * every alias it loads, BouncyCastle keeps the `friendlyName` as written. `getKey` is case
     * insensitive on both, so the entry is fetched under the name the store reported.
     *
     * @throws IllegalStateException naming [subject] and what was wrong with it.
     */
    private fun verifyIdentityAlias(
        store: KeyStore,
        aliases: List<String>,
        expectedAlias: String,
        password: String,
        subject: String,
    ) {
        val alias = aliases.firstOrNull { it.equals(expectedAlias, ignoreCase = true) }
        checkNotNull(alias) {
            "$subject holds no '$expectedAlias' entry (it holds ${aliases.size}: ${aliases.joinToString()})"
        }
        check(store.isKeyEntry(alias)) { "$subject's '$expectedAlias' is not a private-key entry" }
        checkNotNull(unwrapKey(store, alias, password.toCharArray())) {
            "$subject's '$expectedAlias' does not unwrap under this password"
        }
    }

    /**
     * Publish [encoded] as [target], but only once it has been read back and proved to open under
     * [password] with [expectedAliases] intact.
     *
     * The same discipline [changeKeystorePassword] uses, for the same reason: the file being replaced
     * is the account's only copy of its RSA identity, so nothing may touch it until the replacement
     * is known good. The extra step here is the backup copy, which covers the one case
     * [DurableFiles.replace] cannot make atomic — a cross-device move, where it falls back to a plain
     * replacing move and a crash mid-copy could leave a truncated target.
     *
     * ## Every file this can leave in [folder], and what keeps each out of a sync bundle
     *
     * The directory this writes into is `keystore/<user>/`, which is exactly what a keystore sync
     * bundles, so the list has to be exhaustive rather than approximately right:
     *
     * - `<name>.<random>[KeystoreClient.IDENTITY_STORE_TEMP_SUFFIX]` — the replacement, deleted in the
     *   `finally`, left behind only by a power cut. Covered by `DirectoryBundler.TEMP_FILE_SUFFIX`,
     *   the suffix rule that exists because the random infix defeats an exact-name set.
     * - `<name>[KeystoreClient.IDENTITY_STORE_BACKUP_SUFFIX]` — the recovery copy, deleted in the
     *   `finally` unless the dual failure below stranded it. Covered by an exact entry in
     *   `DirectoryBundler.syncExclusions`, which is possible **only** because the name is fixed.
     * - `<name>[KeystoreClient.IDENTITY_STORE_LOCK_SUFFIX]` — the lock this and
     *   [restoreIdentityKeyStoreFromBackup] meet on, created empty on the first commit and never
     *   removed (deleting a lock file another process holds open is how you get two locks and no
     *   exclusion). Also an exact entry in `DirectoryBundler.syncExclusions`.
     *
     * That is the whole set: nothing else here creates a file. All three are filtered outbound and
     * refused inbound, exactly like the keyring.
     *
     * ## Why it is serialised
     *
     * The lock is shared with [restoreIdentityKeyStoreFromBackup] because the two paths reach opposite
     * conclusions about the same files, and a recovery that decided while this method was mid-publish
     * will otherwise put the pre-commit store back over the one this just verified — see
     * [IdentityStoreLock]. A commit that cannot get the lock inside the bound fails without touching
     * anything, which the callers turn into an `Outcome.Error` for the login state machine to retry.
     *
     * Aliases are compared case-insensitively because the reader decides their case: SUN lowercases
     * every alias it loads, BouncyCastle keeps the `friendlyName` as written.
     */
    private fun commitIdentityStore(
        folder: File,
        target: File,
        encoded: ByteArray,
        password: String,
        expectedAliases: List<String>,
    ) {
        // Before the lock: the lock file lives in this directory, so it has to exist first.
        if (!folder.exists()) {
            folder.mkdirs()
        }
        // Artifact lock outermost, identity-store lock inside it. Both are needed: the exclusion
        // list does not keep <user>.pfx out of an unbundle the way this file used to assume, and a
        // user-added keystore named after the account resolves to it as well. The order is fixed —
        // see inArtifactDirectory.
        inArtifactDirectory(folder.path) {
            IdentityStoreLock.withLock(folder, target.name) {
                publishIdentityStore(folder, target, encoded, password, expectedAliases)
            }
        }
    }

    private fun publishIdentityStore(
        folder: File,
        target: File,
        encoded: ByteArray,
        password: String,
        expectedAliases: List<String>,
    ) {
        val tmp = File.createTempFile("${target.name}.", KeystoreClient.IDENTITY_STORE_TEMP_SUFFIX, folder)
        val backup = File(folder, KeystoreClient.identityStoreBackupName(target.name))
        // Whether the `finally` clears the backup path. False until this call has either written that
        // file itself or published a store that makes any older one debris, so a commit that fails
        // before it gets that far cannot remove a backup somebody else is depending on.
        var clearBackup = false
        try {
            FileOutputStream(tmp).use { out ->
                out.write(encoded)
                out.flush()
                out.fd.sync()
            }

            val verification = loadPkcs12(tmp, password.toCharArray())
            val loadedAliases = verification.aliases().toList()
            check(loadedAliases.map(String::lowercase).toSet() == expectedAliases.map(String::lowercase).toSet()) {
                "the rewritten keystore holds ${loadedAliases.size} of ${expectedAliases.size} entries"
            }
            loadedAliases.filter(verification::isKeyEntry).forEach { alias ->
                checkNotNull(unwrapKey(verification, alias, password.toCharArray())) {
                    "the rewritten keystore entry '$alias' does not unwrap under its password"
                }
            }

            val backedUp = target.isFile
            if (backedUp) {
                // Set *before* the write: a half-written backup must not survive this call either.
                // Any stale backup at this path is overwritten, which is what makes "a backup is
                // present" mean "the last commit could not finish" rather than "some commit, once".
                clearBackup = true
                copyDurably(target, backup)
            }
            try {
                DurableFiles.replace(tmp, target)
            } catch (failure: Throwable) {
                // On the atomic path the target was never touched and this changes nothing. On the
                // cross-device fallback the replace is a copy, so it can leave a half-written target
                // — put the backup back over it.
                if (backedUp && !runCatching { DurableFiles.replace(backup, target) }.isSuccess) {
                    // Both halves failed: the live store may be truncated and this file is the only
                    // intact copy of the account's RSA identity. Keep it, say where it is, and let
                    // the next login's restoreIdentityKeyStoreFromBackup finish the job.
                    clearBackup = false
                    KLogger.e(failure) {
                        "could not publish ${target.name} and could not put the original back; the only " +
                            "intact copy is ${backup.absolutePath} and the next login will restore it"
                    }
                }
                throw failure
            }
            // Published. Any backup — this call's, or one stranded by an older commit against a store
            // that no longer exists — is now debris.
            clearBackup = true
        } finally {
            tmp.delete()
            if (clearBackup) backup.delete()
        }
    }

    /** Copy [source] onto [destination], replacing it, with the bytes on the platter before returning. */
    private fun copyDurably(source: File, destination: File) {
        source.inputStream().use { input ->
            FileOutputStream(destination).use { out ->
                input.copyTo(out)
                out.flush()
                out.fd.sync()
            }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun verify(publicKey: Key, data: ByteArray, signature: String): Boolean {
        val valid: Boolean = Signature.getInstance("SHA256withRSA").run {
            initVerify(publicKey as PublicKey)
            update(data)
            val result = verify(Base64.decode(signature))

            result
        }
        return valid
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun sign(privateKey: Key, plainText: String, passPhrase: String): String {
        return Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey as PrivateKey)
            val textBytes = plainText.encodeToByteArray()
            update(textBytes)
            Base64.encode(sign())
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    override fun signFile(filePath: String, privateKey: Key, passPhrase: String): String {
        return Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey as PrivateKey)
            val inputFile = File(filePath)
            val fileBytes = inputFile.readBytes()
            update(fileBytes)

            Base64.encode(sign())
        }
    }

    private fun loadKeyStoreFromPath(
        keystorePath: String,
        keystoreName: String,
        keystorePassword: String,
    ): KeyStore? {
        return runCatching {
            val keystoreFile = File(keystorePath, keystoreName)
            if (!keystoreFile.exists()) {
                KLogger.d { "file dne" }
                return@runCatching null
            }
            loadPkcs12(keystoreFile, keystorePassword.toCharArray())
        }.onFailure {
            KLogger.e(it) { "error loading keystore: ${it.message}" }
        }.getOrNull()
    }

    private fun loadKeyStore( // used with getting the keys
        keyStoreInfo: KeyStoreInfo
    ): KeyStore? {
        val keyStore =
            if (keyStoreInfo.type == KeyStoreType.PKCS12) {
                pkcs12KeyStore()
            } else {
                KeyStore.getInstance(keyStoreInfo.type.type) // JKS, BKS, AndroidKeyStore
            }

        runCatching {
            KLogger.d { "external file path: ${keyStoreInfo.path}" }
            val external = File(keyStoreInfo.path, keyStoreInfo.name)
            KLogger.d { "external file: $external" }
            if (!external.exists()) {
                KLogger.d { "file dne" }
                external.createNewFile()
            }

            keyStore.load(external.inputStream(), keyStoreInfo.keystorePassword.toCharArray())

            keyStore.aliases().toList().forEach {
                KLogger.d { "alias: $it" }
                // keyStore.deleteEntry(it)
            }

            KLogger.d { "loaded keystore ${keyStoreInfo.name} at location: ${keyStoreInfo.path}" }
        }.onFailure {
            KLogger.e(it) { "new default keystore: ${it.message}" }
            keyStore.load(null, keyStoreInfo.keystorePassword.toCharArray())
        }

        return keyStore
    }

    private fun getKeystoreSecretKey(
        keyStoreInfo: KeyStoreInfo,
        keyAlias: String,
        password: CharArray
    ): Key? {
        val keyStore = loadKeyStore(keyStoreInfo)
        return keyStore?.getKey(keyAlias, password)?.also {
            KLogger.i { "existing key, $keyAlias, key: ${it.encoded}" }
        }
    }

    private fun getKeystorePublicKey(
        keyStoreInfo: KeyStoreInfo,
        keyAlias: String,
        password: CharArray
    ): Key? {
        val keyStore = loadKeyStore(keyStoreInfo)
        return keyStore?.getKey(keyAlias, password)?.let {
            // getCertificate is null for symmetric entries or a missing cert chain — surface as
            // "no public key" instead of an NPE.
            keyStore.getCertificate(keyAlias)?.publicKey
        }
    }

    private fun createRootCertificate(keyPair: KeyPair): X509Certificate {
        val nameBuilder = X500NameBuilder(RFC4519Style.INSTANCE).apply {
            addRDN(RFC4519Style.cn, "PassMan")
            addRDN(RFC4519Style.o, "PassMan")
            addRDN(RFC4519Style.ou, "Android")
        }

        val issuer = nameBuilder.build()
        val serial = BigInteger.valueOf(initRandomSerial())
        val pubKey = keyPair.public

        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, KEY_YEARS_VALID)
        val generator = JcaX509v3CertificateBuilder(
            issuer, serial, Calendar.getInstance().time, end.time, issuer, pubKey
        ).apply {
            addExtension(
                Extension.subjectKeyIdentifier,
                false,
                createSubjectKeyIdentifier(pubKey)
            )
            // This is a leaf device-identity cert, not a CA: no basic-constraints CA flag and no
            // cert/CRL-signing usage. Restrict key usage to what the identity key actually does
            // (sign + RSA key/data encipherment for the envelope key wrap).
            addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(false)
            )
            addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(
                    KeyUsage.digitalSignature or KeyUsage.keyEncipherment or KeyUsage.dataEncipherment
                )
            )
            addExtension(
                Extension.extendedKeyUsage,
                false,
                DERSequence(
                    ASN1EncodableVector().apply {
                        add(KeyPurposeId.id_kp_serverAuth)
                        add(KeyPurposeId.id_kp_clientAuth)
                    }
                )
            )
        }

        return signCertificate(generator, keyPair)
    }

    private fun signCertificate(
        certbuilder: X509v3CertificateBuilder,
        keyPair: KeyPair
    ): X509Certificate {
        val signer =
            JcaContentSignerBuilder("SHA512withRSA") // dsaWithSha1 SHA512WithECDSA SHA512withRSA
                .build(keyPair.private)

        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider())
            .getCertificate(certbuilder.build(signer))
    }

    private fun createSubjectKeyIdentifier(key: Key): SubjectKeyIdentifier? {
        val bIn = ByteArrayInputStream(key.encoded)
        var inputStream: ASN1InputStream? = null
        return try {
            inputStream = ASN1InputStream(bIn)
            val seq: ASN1Sequence = inputStream.readObject() as ASN1Sequence
            val info = SubjectPublicKeyInfo.getInstance(seq)
            BcX509ExtensionUtils().createSubjectKeyIdentifier(info)
        } finally {
            inputStream?.close()
        }
    }

    private fun initRandomSerial(): Long {
        val rnd = SecureRandom()
        // rnd.setSeed(System.currentTimeMillis())
        // prevent browser certificate caches, cause of doubled serial numbers
        // using 48bit random number
        var sl = rnd.nextLong() shl 32 or (rnd.nextLong() and 0xFFFFFFFF)
        // let reserve of 16 bit for increasing, serials have to be positive
        sl = sl and 0x0000FFFFFFFFFFFFL
        return sl
    }

    override fun unwrapKey(keyStore: KeyStore, alias: String, password: CharArray): Key? {
        val needsDemote = keyStore.provider.name == "SUN" || keyStore.provider.name == "SunJSSE"
        return runCatching {
            if (needsDemote) {
                withBouncyCastleDemoted { keyStore.getKey(alias, password) }
            } else {
                keyStore.getKey(alias, password)
            }
        }.onFailure {
            KLogger.w(it) { "unwrapKey failed for '$alias' via ${keyStore.provider.name}" }
        }.getOrNull()
    }

}
