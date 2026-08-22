package ai.passman.repo.repositories

import ai.passman.cache.di.passmanSessionScope
import ai.passman.crypto.Crypto
import ai.passman.crypto.CryptoKey
import ai.passman.crypto.io.ArtifactDirectoryLock
import ai.passman.crypto.io.DurableFiles
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.keys.model.DSA
import ai.passman.keys.model.ECDSA
import ai.passman.keys.model.ED25519
import ai.passman.keys.model.ED448
import ai.passman.keys.model.EDDSA
import ai.passman.keys.model.ELGAMAL
import ai.passman.keys.model.RSA
import ai.passman.pgp.bundled.BundledDeveloperKey
import ai.passman.pgp.service.PgpClient
import ai.passman.pgp.utils.PgpKeyRingSupport
import ai.passman.pgp.utils.PgpKeys
import ai.passman.pgp.utils.inspectKeyRingSupport
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.platform.transfer.PgpTransferService
import ai.passman.repo.Platform
import ai.passman.repo.createNewFileWithAppendedName
import ai.passman.repo.datamapper.toPgpKey
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.repo.model.AlgorithmDetails
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.base.model.isSuccessful
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.*
import ai.passman.domain.pgp.repository.PgpPreferences
import ai.passman.domain.pgp.repository.PgpRepository
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import org.koin.core.qualifier.named
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import org.bouncycastle.bcpg.SecretKeyPacket
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

internal class LocalPgpRepository(
    private val platform: Platform,
    private val coroutinesContextFacade: CoroutinesContextFacade,
    private val pgpClient: PgpClient,
    private val userPreferences: UserPreferences,
    private val pgpTransferService: PgpTransferService,
    private val pgpPreferences: PgpPreferences,
) : PgpRepository {
    private val pgpDir = "${platform.getLocalPath()}${File.separator}pgp${File.separator}"

    /**
     * Run [block] holding `pgp/<userName>/`'s artifact-directory lock.
     *
     * This is the directory a PGP sync unbundles into, and `unbundle` displaces the file it is about
     * to replace by renaming it away and then renaming the inbound version in. Without this, a key
     * edit landing between those two steps was overwritten having never been preserved.
     *
     * It is taken **here** rather than inside [PgpClient] deliberately. `PgpClient` is handed file
     * paths and knows nothing about artifact directories, so locking there would mean deriving the
     * directory from a ring file's own parent — the same mistake `DirectoryBundler` documents for the
     * conflict store, where a nested entry yields a child of the bundled tree instead of the tree
     * itself. This class owns `pgpDir`, so it can name the directory the lock is actually keyed on.
     *
     * The consequence is that a future direct `PgpClient` write from somewhere else would miss the
     * lock. Every mutating `PgpClient` method is called from this class and nowhere else today, but
     * nothing enforces that — `LocalPgpRepositoryTest` pins that each call site here takes the lock,
     * which is not the same guarantee. A new caller of `PgpClient` has to take it too.
     *
     * Read-modify-write callers hold it across the **read** as well: rewriting a ring means parsing
     * the live file and encoding a new one over it, which is only correct if nothing replaces the
     * file in between.
     */
    private fun <T> inKeyDirectory(userName: String, block: () -> T): T =
        ArtifactDirectoryLock.withLock(File("$pgpDir$userName"), block)

    /**
     * What the bundled-developer-key write decided, carried out of the lock so the suspending
     * preference write can happen after it is released.
     */
    private enum class DeveloperKeyOutcome { OCCUPIED, ALREADY_PRESENT, WRITTEN }

    override suspend fun getKeys(): List<PgpKeyPair> = withContext(coroutinesContextFacade.io) {
        val user = userPreferences.getUser() as AppUser.LoggedIn

        val publicKeys = mutableMapOf<String, RingEntry>()
        val secretKeys = mutableMapOf<String, PgpKey>()
        val pairedKeys = mutableListOf<PgpKeyPair>()

        readKeyEntries(user.userName).forEach { entry ->
            val key = entry.key
            if (key.type == PgpKeyType.Secret) {
                secretKeys[key.keyId.toString()] = key
            } else {
                val existing = publicKeys[key.keyId.toString()]
                // A public entry whose file actually contained a PGPPublicKeyRing must never be
                // displaced by the public half synthesized from a secret ring: the entry's path
                // is what share flows hand out. Only when no public ring file exists does the
                // synthesized entry (pointing at the secret file) remain the listed one. Within
                // the same provenance the FIRST file in name order wins, matching how
                // getPublicKeyPath picks a file, so details and share agree on the same file.
                if (existing == null || (entry.fromPublicRing && !existing.fromPublicRing)) {
                    publicKeys[key.keyId.toString()] = entry
                }
            }
        }

        publicKeys.forEach { (_, entry) ->
            val publicKey = entry.key
            secretKeys.values.find { it.keyId == publicKey.keyId }?.let { secretKey ->
                pairedKeys.add(PgpKeyPair(publicKey, secretKey))
            } ?: pairedKeys.add(PgpKeyPair(publicKey = publicKey, secretKey = null))
        }

        pairedKeys
    }

    override suspend fun getPublicKeyPath(keyId: Long): Outcome<String> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            // Share safety: only a file that parsed as a PGPPublicKeyRing and nothing else may
            // leave the app. The listed pair's publicKey.path can legitimately point at a
            // secret-ring file when no public ring exists (see getKeys), and an imported file
            // can hold a public AND a secret ring concatenated (the GnuPG keyring layout) — the
            // whole file is what gets shared, so any file that also produced a Secret entry is
            // out. If no clean public ring file carries this key, fail rather than fall back.
            val entries = readKeyEntries(user.userName)
            val secretPaths = entries.filter { it.key.type == PgpKeyType.Secret }.map { it.key.path }.toSet()
            entries
                .firstOrNull { it.fromPublicRing && it.key.keyId == keyId && it.key.path !in secretPaths }
                ?.let { entry ->
                    // A ring carrying an algorithm this build cannot read is not the ring it
                    // appears to be: BouncyCastle drops an unknown v4 subkey along with every
                    // subkey after it, so what we would hand out is a silently truncated key.
                    when (val support = supportOf(entry.key.path)) {
                        is PgpKeyRingSupport.UnsupportedAlgorithm -> Outcome.Error(
                            "this key uses algorithm ${support.algorithmId}, which this version cannot read",
                            PgpFailure.UnsupportedKeyAlgorithm(support.algorithmId),
                        )

                        else -> Outcome.Success(entry.key.path)
                    }
                }
                ?: Outcome.Error("no public key ring file for key", PgpFailure.SharePublicKeyFailure)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to resolve public key path" }
        }.getOrElse {
            Outcome.Error("failed to resolve public key path", PgpFailure.SharePublicKeyFailure)
        }
    }

    override suspend fun getSecretKeyPath(keyId: Long, passphrase: String): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                val user = userPreferences.getUser() as AppUser.LoggedIn
                val files = keyFiles(user.userName)
                var refusedSharedFile = false
                for (file in files) {
                    val entries = runCatching { processKeyRing(file.absolutePath, file.name) }
                        .getOrElse {
                            if (it is CancellationException) throw it
                            emptyList()
                        }
                    if (entries.none { it.key.type == PgpKeyType.Secret && it.key.keyId == keyId }) continue
                    // The whole FILE is what leaves the app. A file that also carries other
                    // keys (imported collection) or a genuine public ring (combined GnuPG
                    // layout) is not this key's standalone secret ring — mirror deletePgpKey
                    // and refuse it rather than leak whatever else it holds.
                    if (entries.any { it.key.keyId != keyId } || entries.any { it.fromPublicRing }) {
                        KLogger.e { "getSecretKeyPath: ${file.name} is not a standalone secret ring for the key; skipping" }
                        refusedSharedFile = true
                        continue
                    }
                    val support = supportOf(file.absolutePath)
                    if (support is PgpKeyRingSupport.UnsupportedAlgorithm) {
                        return@withContext Outcome.Error(
                            "this key uses algorithm ${support.algorithmId}, which this version cannot read",
                            PgpFailure.UnsupportedKeyAlgorithm(support.algorithmId),
                        )
                    }
                    return@withContext verifyPassphraseUnlocks(file, keyId, passphrase)
                }
                if (refusedSharedFile) {
                    Outcome.Error(
                        "the secret ring shares a file with other keys or rings; refusing to export it",
                        PgpFailure.ExportPrivateKeyFailure,
                    )
                } else {
                    Outcome.Error("no secret key ring file for key", PgpFailure.ExportPrivateKeyFailure)
                }
            }.getOrElse {
                if (it is CancellationException) throw it
                KLogger.e(it) { "failed to resolve secret key path" }
                Outcome.Error("failed to resolve secret key path", PgpFailure.ExportPrivateKeyFailure)
            }
        }

    /**
     * The passphrase gate for private-key export. "No exception" is NOT proof of an unlock:
     * BC's extractPrivateKey returns null for GNU-dummy stubs (gpg --export-secret-subkeys
     * primaries) instead of throwing, and passes the data through untouched for keys stored
     * without passphrase protection — under any passphrase. So the extracted key itself is
     * required, its keyID must match, and an unprotected key is refused outright (the export
     * contract promises passphrase-encrypted armor).
     */
    private fun verifyPassphraseUnlocks(file: File, keyId: Long, passphrase: String): Outcome<String> {
        val ring = FileInputStream(file).use { stream ->
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(stream), JcaKeyFingerprintCalculator())
            generateSequence { factory.nextObject() }.filterIsInstance<PGPSecretKeyRing>().firstOrNull()
        } ?: return Outcome.Error("no secret key ring in file", PgpFailure.ExportPrivateKeyFailure)

        val secretKey = ring.getSecretKey(keyId)
            ?: return Outcome.Error("secret key not present in ring", PgpFailure.ExportPrivateKeyFailure)
        if (secretKey.s2KUsage == SecretKeyPacket.USAGE_NONE) {
            KLogger.e { "getSecretKeyPath: ${file.name} holds an unprotected secret key; refusing to export" }
            return Outcome.Error("secret key is not passphrase-protected", PgpFailure.ExportPrivateKeyFailure)
        }

        val privateKey = try {
            secretKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray())
            )
        } catch (e: PGPException) {
            // Checksum mismatch, AEAD tag failure, ... — whatever the protection mode, a
            // PGPException out of the extract means the passphrase did not unlock the key.
            KLogger.e(e) { "private key export refused: unlock failed for ${file.name}" }
            return Outcome.Error("wrong passphrase", PgpFailure.WrongPassword)
        }
        if (privateKey == null || privateKey.keyID != keyId) {
            KLogger.e { "getSecretKeyPath: ${file.name} extracted no usable private key (dummy stub?)" }
            return Outcome.Error("secret key could not be verified", PgpFailure.ExportPrivateKeyFailure)
        }
        return Outcome.Success(file.absolutePath)
    }

    /**
     * The account's key files, in name order, temp staging files excluded. Writers stage
     * `<name>.<random>.tmp` beside their target before the atomic replace (this repository's
     * developer-key import included), and a crashed writer leaves that debris behind; listing
     * it would be worse than noise — the first-in-name-order dedup could hand out a path that
     * is about to vanish. Same suffix contract as DirectoryBundler's sync exclusion, so what
     * the listing ignores is exactly what sync never ships.
     */
    private fun keyFiles(userName: String): List<File> =
        File("$pgpDir$userName")
            .listFiles { file ->
                file.isFile && !file.name.endsWith(DirectoryBundler.TEMP_FILE_SUFFIX)
            }
            .orEmpty()
            .sortedBy { it.name }

    /**
     * Every key entry in the user's key directory, in file-name order so callers that dedup by
     * keyId are deterministic — File.listFiles() order is unspecified. The sort is load-bearing:
     * LocalPgpRepositoryTest's dedup tests rely on it, and without it they degrade to
     * order-dependent flakes. A file that fails to parse is logged and skipped instead of
     * failing the whole listing.
     */
    private fun readKeyEntries(userName: String): List<RingEntry> =
        keyFiles(userName)
            .flatMap { file ->
                runCatching { processKeyRing(file.absolutePath, file.name) }
                    .getOrElse {
                        if (it is CancellationException) throw it
                        KLogger.e(it) { "skipping unparseable pgp key file: ${file.name}" }
                        emptyList()
                    }
            }

    override suspend fun getKey(keyId: Long): PgpKeyPair? = withContext(coroutinesContextFacade.io) {
        getKeys().find { key -> key.publicKey.keyId == keyId }
    }

    override suspend fun createPgpKey(
        name: String,
        email: String,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        kotlin.runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val pgpSecretRingPath = "$pgpDir${user.userName}${File.separator}${name}_secret_ring.asc"
            val pgpPublicRingPath = "$pgpDir${user.userName}${File.separator}${name}_public_ring.asc"

            // The whole decision-and-write, including key generation, is inside the lock: the
            // `exists()` branch below chooses between generating and re-opening, and acting on that
            // answer after a sync has replaced the file would write a ring built from bytes that are
            // no longer there. A long generation can therefore make a concurrent inbound push
            // exhaust the lock budget and be rejected; the peer retries, and losing a key would not
            // be recoverable.
            inKeyDirectory(user.userName) {
                val secretRingFile = File(pgpSecretRingPath)
                val (pgpSecretRing, pgpPublicRing) = if (!secretRingFile.exists()) {
                    val algo = when (algorithm) {
                        PgpKeyAlgorithm.DSA_SIGN -> DSA
                        PgpKeyAlgorithm.RSA_SIGN -> RSA
                        PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> ELGAMAL
                        PgpKeyAlgorithm.RSA_ENCRYPT -> RSA
                        PgpKeyAlgorithm.ED25519 -> EDDSA
                        PgpKeyAlgorithm.ECDSA_ECDH -> ECDSA
                        PgpKeyAlgorithm.ED25519_X25519 -> ED25519
                        PgpKeyAlgorithm.ED448_X448 -> ED448
                    }
                    val keyRingGenerator = PgpKeys.createPgpKeyRingGenerator(
                        userId = UserId(name = name, email = email, isRevoked = false).toString(),
                        algorithm = algo,
                        length = length,
                        expirationInSeconds = expiration,
                        password = password,
                    )
                    keyRingGenerator.generateSecretKeyRing()
                    val secretRing = keyRingGenerator.generateSecretKeyRing()
                    val publicRing = keyRingGenerator.generatePublicKeyRing()
                    secretRing to publicRing
                } else {
                    val secretRing = pgpClient.getSecretKeyRing(pgpSecretRingPath, password)
                    val publicRing = pgpClient.getPublicKeyRing(pgpPublicRingPath)
                    secretRing to publicRing
                }

                PgpKeys.saveSecretKeyRingToFile(pgpSecretRing, pgpSecretRingPath)
                PgpKeys.savePublicKeyRingToFile(pgpPublicRing, pgpPublicRingPath)
            }

            Outcome.Success("")
        }.onFailure {
            KLogger.e(it) {
                "failed to create new key"
            }
        }.getOrElse {
            Outcome.Error("failed to create new key", PgpFailure.GeneralPgpError("failed to create new key"))
        }

    }

    override suspend fun encryptPgpMessage(plainText: String, publicKeyPath: String): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                pgpClient.encryptPgpMessage(plainText, publicKeyPath)
            }.onFailure {
                KLogger.e(it) { "failed to decrypt message, ${it.message}" }
            }.getOrNull() ?: Outcome.Error("", PgpFailure.EncryptFailure)
        }

    override suspend fun encryptPgpFile(filePath: String, publicKeyPath: String): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            val newFile = createNewFileWithAppendedName(filePath, "encrypted")
            pgpClient.encryptPgpFile(filePath, newFile.absolutePath, publicKeyPath)
        }

    override suspend fun decryptPgpMessage(encryptedText: String, secretKeyPath: String, keyPassword: String): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            kotlin.runCatching {
                pgpClient.decryptPgpMessage(encryptedText, secretKeyPath, keyPassword)
            }.onFailure {
                KLogger.e(it) { "failed to decrypt message, ${it.message}" }
                if (it.message?.contains("checksum") == true) {
                    Outcome.Error("wrong password", PgpFailure.WrongPassword)
                } else {
                    Outcome.Error("wrong password", PgpFailure.DecryptFailure)
                }
            }.getOrNull() ?: Outcome.Error("", PgpFailure.DecryptFailure)
        }

    override suspend fun decryptPgpFile(
        encryptedFilePath: String,
        secretKeyPath: String,
        keyPassword: String
    ): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                val newFile = createNewFileWithAppendedName(encryptedFilePath, "decrypted")
                pgpClient.decryptPgpFile(encryptedFilePath, newFile.absolutePath, secretKeyPath, keyPassword)
            }.onFailure {
                if (it.message?.contains("checksum") == true) {
                    Outcome.Error("wrong password", PgpFailure.WrongPassword)
                } else {
                    Outcome.Error("decrypt file error", PgpFailure.DecryptFailure)
                }
            }.getOrNull() ?: Outcome.Error("decrypt file error", PgpFailure.DecryptFailure)
        }

    override suspend fun clearSign(plainText: String, privateKeyPath: String, keyPassword: String): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                pgpClient.clearSign(plainText, privateKeyPath, keyPassword)
            }.onFailure {
                KLogger.e(it) { "failed to decrypt message, ${it.message}" }
                if (it.message?.contains("checksum") == true) {
                    Outcome.Error("wrong password", PgpFailure.WrongPassword)
                } else {
                    Outcome.Error("clear sign failure", PgpFailure.SignFailure)
                }
            }.getOrNull() ?: Outcome.Error("clear sign failure", PgpFailure.SignFailure)
        }

    override suspend fun clearSignFile(
        plainFilePath: String,
        privateKeyPath: String,
        keyPassword: String
    ): Outcome<String> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                val newFile = createNewFileWithAppendedName(plainFilePath, "signed")
                pgpClient.clearSignFile(plainFilePath, newFile.absolutePath, privateKeyPath, keyPassword)
            }.onFailure {
                KLogger.e(it) { "failed to decrypt message, ${it.message}" }
                if (it.message?.contains("checksum") == true) {
                    Outcome.Error("wrong password", PgpFailure.WrongPassword)
                } else {
                    Outcome.Error("clear sign failure", PgpFailure.SignFailure)
                }
            }.getOrNull() ?: Outcome.Error("clear sign failure", PgpFailure.SignFailure)
        }

    override suspend fun sign(
        plainText: String,
        privateKeyPath: String,
        passPhrase: String,
        armor: Boolean,
        digestName: String
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        pgpClient.sign(plainText, privateKeyPath, passPhrase, armor, digestName)
    }

    override suspend fun verifyClearSignature(encryptedText: String, publicKeyPath: String): Outcome<Unit> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                pgpClient.verifyClearSignature(encryptedText, publicKeyPath)
            }.onFailure {
                KLogger.e(it) { "failed to verify signature, ${it.message}" }
            }.getOrNull() ?: Outcome.Error("failed to verify signature", PgpFailure.SignVerifyFailure)
        }

    override suspend fun verifyClearSignatureFile(encryptedFilePath: String, publicKeyPath: String): Outcome<Unit> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                pgpClient.verifyClearSignatureFile(encryptedFilePath, publicKeyPath)
            }.onFailure {
                KLogger.e(it) { "failed to verify signature, ${it.message}" }
            }.getOrNull() ?: Outcome.Error("failed to verify signature", PgpFailure.SignVerifyFailure)
        }

    override suspend fun verifySignature(signatureText: String, publicKeyPath: String): Outcome<Unit> =
        withContext(coroutinesContextFacade.io) {
            runCatching {
                pgpClient.verifySignature(signatureText, publicKeyPath)
            }.onFailure {
                KLogger.e(it) { "failed to verify signature, ${it.message}" }
            }.getOrNull() ?: Outcome.Error("failed to verify signature", PgpFailure.SignVerifyFailure)
        }

    override suspend fun signAndEncrypt(
        plainText: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        runCatching {
            pgpClient.signAndEncrypt(plainText, publicKeyPath, privateKeyPath, keyPassword)
        }.onFailure {
            KLogger.e(it) { "failed to sign and encrypt, ${it.message}" }
            if (it.message?.contains("checksum") == true) {
                Outcome.Error("wrong password", PgpFailure.WrongPassword)
            } else {
                Outcome.Error("clear sign failure", PgpFailure.SignAndEncryptFailure)
            }
        }.getOrNull() ?: Outcome.Error("failed to sign and encrypt", PgpFailure.SignAndEncryptFailure)
    }

    override suspend fun signAndEncryptFile(
        plainFilePath: String,
        publicKeyPath: String,
        privateKeyPath: String,
        keyPassword: String
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val newFile = createNewFileWithAppendedName(plainFilePath, "encrypted_signed")
            pgpClient.signAndEncryptFile(
                plainFilePath = plainFilePath,
                newFilePath = newFile.absolutePath,
                publicKeyPath = publicKeyPath,
                privateKeyPath = privateKeyPath,
                keyPassword = keyPassword,
            )
        }.onFailure {
            KLogger.e(it) { "failed to decrypt message, ${it.message}" }
            if (it.message?.contains("checksum") == true) {
                Outcome.Error("wrong password", PgpFailure.WrongPassword)
            } else {
                Outcome.Error("clear sign failure", PgpFailure.SignAndEncryptFailure)
            }
        }.getOrNull() ?: Outcome.Error("clear sign failure", PgpFailure.SignAndEncryptFailure)
    }

    override suspend fun verifyAndDecrypt(
        encryptedText: String,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        runCatching {
            pgpClient.verifyAndDecrypt(encryptedText, privateKeyPath, keyPassword, publicKeyPath)
        }.onFailure {
            KLogger.e(it) { "failed to decrypt and verify, ${it.message}" }
            if (it.message?.contains("checksum") == true) {
                Outcome.Error("wrong password", PgpFailure.WrongPassword)
            } else {
                Outcome.Error("failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
            }
        }.getOrNull() ?: Outcome.Error("failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
    }

    override suspend fun verifyAndDecryptFile(
        encryptedFilePath: String,
        privateKeyPath: String,
        keyPassword: String,
        publicKeyPath: String
    ): Outcome<String> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val newFile = createNewFileWithAppendedName(encryptedFilePath, "decrypted_verified")
            pgpClient.verifyAndDecryptFile(encryptedFilePath, newFile, privateKeyPath, keyPassword, publicKeyPath)
        }.onFailure {
            KLogger.e(it) { "failed to decrypt and verify, ${it.message}" }
            if (it.message?.contains("checksum") == true) {
                Outcome.Error("wrong password", PgpFailure.WrongPassword)
            } else {
                Outcome.Error("failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
            }
        }.getOrNull() ?: Outcome.Error("failed to decrypt and verify", PgpFailure.DecryptAndVerifyFailure)
    }

    override suspend fun modifyUserId(
        keyPair: PgpKeyPair,
        password: String,
        userId: UserId,
        userIdAction: UserIdAction
    ): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            // Parses the live rings and encodes new ones over them - read and write both inside.
            inKeyDirectory(user.userName) {
                pgpClient.modifyUserId(keyPair = keyPair, userId.toString(), password, userIdAction)
            }
            Outcome.Success(Unit)
        }.onFailure {
            KLogger.e(it) {
                "failed to add user id, ${it.message}"
            }
        } .getOrNull() ?: Outcome.Error("failed to add user id", when (userIdAction) {
            UserIdAction.ADD -> PgpFailure.AddUserIdFailure
            UserIdAction.REMOVE -> PgpFailure.RemoveUserIdFailure
            UserIdAction.REVOKE -> PgpFailure.RevokeUserIdFailure
        })
    }

    override suspend fun addSubKey(
        keyPair: PgpKeyPair,
        password: String,
        algorithm: PgpKeyAlgorithm,
        length: Int,
        expiration: Long
    ): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val algorithmDetails = when (algorithm) {
                PgpKeyAlgorithm.DSA_SIGN -> {
                    AlgorithmDetails(
                        algorithm = "DSA",
                        type = PGPPublicKey.DSA,
                        flags = KeyFlags.SIGN_DATA
                    )
                }
                PgpKeyAlgorithm.RSA_SIGN -> {
                    AlgorithmDetails(
                        algorithm = "RSA",
                        type = PGPPublicKey.RSA_GENERAL,
                        flags = KeyFlags.SIGN_DATA
                    )
                }
                PgpKeyAlgorithm.ELGAMAL_ENCRYPT -> {
                    AlgorithmDetails(
                        algorithm = "ElGamal",
                        type = PGPPublicKey.ELGAMAL_ENCRYPT,
                        flags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
                    )
                }
                PgpKeyAlgorithm.RSA_ENCRYPT -> {
                    AlgorithmDetails(
                        algorithm = "RSA",
                        type = PGPPublicKey.RSA_GENERAL,
                        flags = KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
                    )
                }
                // Adding a subkey to an existing ring goes through PgpClient.addSubKey, which
                // dispatches on an algorithm *string* and only knows RSA, DSA and ElGamal. Every
                // curve option is refused here rather than silently falling back to RSA, which is
                // what that method's own `else` branch would do.
                PgpKeyAlgorithm.ED25519 -> error("Ed25519 subkeys are not supported")
                PgpKeyAlgorithm.ECDSA_ECDH -> error("ECDSA subkeys are not supported")
                PgpKeyAlgorithm.ED25519_X25519 -> error("Ed25519/X25519 subkeys are not supported")
                PgpKeyAlgorithm.ED448_X448 -> error("Ed448/X448 subkeys are not supported")
            }

            val user = userPreferences.getUser() as AppUser.LoggedIn
            // Parses the live rings and encodes new ones over them - read and write both inside.
            inKeyDirectory(user.userName) {
                pgpClient.addSubKey(
                    keyPair = keyPair,
                    passphrase = password,
                    algorithm = algorithmDetails.algorithm,
                    length = length,
                    keyFlags = algorithmDetails.flags,
                    expirationTimeInSeconds = expiration,
                )
            }

            Outcome.Success(Unit)
        }.onFailure {
            KLogger.e(it) {
                "failed to add sub key, ${it.message}"
            }
        }.getOrElse {
            Outcome.Error("failed to add sub key: ${it.message}", PgpFailure.AddSubKeyFailure)
        }
    }

    override suspend fun modifySubKey(
        keyPair: PgpKeyPair,
        password: String,
        subKeyId: String,
        action: SubKeyAction
    ): Outcome<Unit> =
        withContext(coroutinesContextFacade.io) {
            kotlin.runCatching {
                val user = userPreferences.getUser() as AppUser.LoggedIn
                // Parses the live rings and encodes new ones over them - read and write both inside.
                inKeyDirectory(user.userName) {
                    when (action) {
                        SubKeyAction.REMOVE -> pgpClient.removeSubkey(keyPair, password, subKeyId)
                        SubKeyAction.REVOKE -> pgpClient.revokeSubkey(keyPair, password, subKeyId)
                    }
                }

                Outcome.Success(Unit)
            }.onFailure {
                KLogger.e(it) { "failed to modify subkey, ${it.message}" }
            }.getOrNull() ?: Outcome.Error("", when (action) {
                SubKeyAction.REMOVE -> PgpFailure.RemoveSubKeyFailure
                SubKeyAction.REVOKE -> PgpFailure.RevokeSubKeyFailure
            })
        }

    override suspend fun changeKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long) {

    }

    override suspend fun changeSubKeyExpiry(keyPair: PgpKeyPair, password: String, newExpiry: Long) {

    }

    override suspend fun changeKeyPassword(
        keyPair: PgpKeyPair,
        oldPassword: String,
        newPassword: String
    ): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            // Parses the live secret ring under the old passphrase and encodes a new one over it -
            // read and write both inside.
            inKeyDirectory(user.userName) {
                pgpClient.changePassword(keyPair, oldPassword, newPassword)
            }
            Outcome.Success(Unit)
        }.onFailure {
            KLogger.e(it) { "failed to modify subkey, ${it.message}" }
        }.getOrNull() ?: Outcome.Error("", PgpFailure.ChangePasswordFailure)
    }

    override suspend fun importPgpFile(path: String): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val source = Paths.get(path)
            val destinationPath = "$pgpDir${user.userName}${File.separator}${source.fileName}"
            val destination = Paths.get(destinationPath)

            // Import used to be a bare file copy: anything the picker returned landed in the key
            // directory and "succeeded", then vanished from the listing because it never parsed.
            // Decide before writing, and say why when the answer is no.
            when (val support = FileInputStream(source.toFile()).use { inspectKeyRingSupport(it) }) {
                is PgpKeyRingSupport.NotAKeyRing ->
                    return@runCatching Outcome.Error(
                        "that file is not an OpenPGP key ring",
                        PgpFailure.ImportKeyFailure,
                    )

                is PgpKeyRingSupport.UnsupportedAlgorithm ->
                    return@runCatching Outcome.Error(
                        "this key uses algorithm ${support.algorithmId}, which this version cannot read",
                        PgpFailure.UnsupportedKeyAlgorithm(support.algorithmId),
                    )

                is PgpKeyRingSupport.Supported -> Unit
            }

            // Only the write is locked. Everything above inspected the SOURCE file, which is
            // outside the artifact directory, so there is no read here to keep atomic with it.
            inKeyDirectory(user.userName) {
                // The per-user dir otherwise only exists once key generation has run; importing
                // into a fresh account must not depend on that.
                destination.parent?.let { Files.createDirectories(it) }
                // Import keeps the SOURCE's filename, so it can land on a ring that is already
                // there — and `REPLACE_EXISTING` destroyed it. Sync stopped being able to lose key
                // material; this was the same loss through a different door, and the invariant is
                // about the artifact, not about which code path reached it. The displaced ring goes
                // where a sync-displaced one goes, and is restorable from the same screen.
                // Staged first, displaced second, installed third - and the order is the fix.
                //
                // Preserving before reading the source meant that importing a file which IS the
                // destination destroyed it: the preserve renamed it into the conflict store and the
                // copy then read a path that no longer existed. `Files.copy(f, f)` had been a
                // harmless no-op before, so adding the preserve turned "pick the file you already
                // have" into data loss. Staging first also means a failed read - vanished source,
                // full disk, bad media - happens while the live file is still live.
                val staged = File.createTempFile(
                    "${destination.fileName}.",
                    DirectoryBundler.TEMP_FILE_SUFFIX,
                    destination.parent.toFile(),
                )
                try {
                    Files.copy(source, staged.toPath(), StandardCopyOption.REPLACE_EXISTING)
                    DirectoryBundler.preserveBeforeOverwriting(
                        File("$pgpDir${user.userName}"),
                        source.fileName.toString(),
                    )
                    DurableFiles.replace(staged, destination.toFile())
                } finally {
                    staged.delete()
                }
            }

            Outcome.Success(Unit)
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to copy import file" }
        }.getOrElse {
            Outcome.Error("failed to import file", PgpFailure.ImportKeyFailure)
        }
    }

    override suspend fun importBundledDeveloperKey(force: Boolean): Outcome<Boolean> =
        importDeveloperKey(force, BundledDeveloperKey.ARMOR, BundledDeveloperKey.FINGERPRINT)

    /**
     * Seam behind [importBundledDeveloperKey]: production only ever passes the bundled constants;
     * the test passes a mismatched pin (and a secret-ring armor) to prove the guard refuses them.
     */
    internal suspend fun importDeveloperKey(
        force: Boolean,
        armor: String,
        pinnedFingerprint: String,
    ): Outcome<Boolean> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            if (!force && pgpPreferences.isDeveloperKeyImported(user.userName)) {
                // The once-per-account import already ran. Deliberately NOT "file exists":
                // a user who deleted the key keeps it deleted until the explicit re-import.
                return@withContext Outcome.Success(false)
            }

            // Tamper guard: the armor must still parse to exactly one public key ring whose
            // primary fingerprint is the pinned one. Anything else — parse failure, secret-key
            // packets, extra rings, another key — is refused before a byte hits disk.
            val armorBytes = armor.encodeToByteArray()
            val fingerprint = soleImportablePublicRingFingerprint(armorBytes)
            if (fingerprint != pinnedFingerprint) {
                KLogger.e { "bundled developer key failed fingerprint verification; refusing to install it" }
                return@withContext Outcome.Error(
                    "bundled developer key failed verification",
                    PgpFailure.ImportKeyFailure,
                )
            }

            val destination = File("$pgpDir${user.userName}${File.separator}${BundledDeveloperKey.FILE_NAME}")

            // The occupant guard reads `destination` and then decides whether to write over it, so
            // both halves are inside the lock: a sync landing between them would be overwritten on
            // the strength of a check made against bytes it had already replaced. The decision comes
            // back as a value rather than an early return because the lock takes a plain lambda, and
            // the suspending preference write has to happen outside it — this is a blocking lock and
            // must not be held across a suspension point.
            val outcome = inKeyDirectory(user.userName) {
                // Occupant guard: sync copies whatever a peer had under this name, so the slot may
                // already hold key material. The developer key's own content (a peer's earlier
                // import) is treated as already-imported for auto and refreshable for force; ANY
                // other content — a different key, or something that does not parse — is
                // irreplaceable user data and neither mode may overwrite it.
                if (destination.exists()) {
                    val occupantFingerprint = runCatching {
                        soleImportablePublicRingFingerprint(destination.readBytes())
                    }.getOrElse {
                        if (it is CancellationException) throw it
                        null
                    }
                    if (occupantFingerprint != pinnedFingerprint) {
                        KLogger.e { "refusing to overwrite ${destination.name}: it does not hold the developer key" }
                        return@inKeyDirectory DeveloperKeyOutcome.OCCUPIED
                    }
                    // A paired device already installed it; record that and skip the write.
                    if (!force) return@inKeyDirectory DeveloperKeyOutcome.ALREADY_PRESENT
                }

                // Fresh accounts have no per-user dir yet (importPgpFile parity).
                destination.parentFile?.let { Files.createDirectories(it.toPath()) }
                // Write-to-temp + atomic replace: getKeys/sync must never observe a half-written
                // ring. `<name>.<random>` + TEMP_FILE_SUFFIX is the staging pattern KeyringStore /
                // HybridKeyManager / MlDsaKeyManager use; the suffix keeps the staging file out of
                // keyFiles listings and out of sync bundles.
                val temp = File.createTempFile("${destination.name}.", DirectoryBundler.TEMP_FILE_SUFFIX, destination.parentFile)
                try {
                    temp.writeBytes(armorBytes)
                    DurableFiles.replace(temp, destination)
                } finally {
                    temp.delete() // no-op after a successful move; cleanup after a failed write
                }
                DeveloperKeyOutcome.WRITTEN
            }

            when (outcome) {
                DeveloperKeyOutcome.OCCUPIED -> return@withContext Outcome.Error(
                    "another key occupies the developer key file; refusing to overwrite it",
                    PgpFailure.ImportKeyFailure,
                )
                // Recorded only after verification AND the write both succeeded.
                DeveloperKeyOutcome.ALREADY_PRESENT -> {
                    pgpPreferences.setDeveloperKeyImported(user.userName)
                    Outcome.Success(false)
                }
                DeveloperKeyOutcome.WRITTEN -> {
                    pgpPreferences.setDeveloperKeyImported(user.userName)
                    Outcome.Success(true)
                }
            }
        }.onFailure {
            if (it is CancellationException) throw it
            KLogger.e(it) { "failed to import bundled developer key" }
        }.getOrElse {
            Outcome.Error("failed to import developer key", PgpFailure.ImportKeyFailure)
        }
    }

    /**
     * The primary-key fingerprint (uppercase hex, the app-wide display format) of [armorBytes],
     * or null unless the blob is EXACTLY one [PGPPublicKeyRing] and nothing else — any
     * secret-key packet or additional ring disqualifies the whole blob.
     */
    private fun soleImportablePublicRingFingerprint(armorBytes: ByteArray): String? {
        // "Exactly one public ring" says nothing about what is inside it, and BouncyCastle reports
        // a ring whose unknown subkeys it dropped as perfectly well-formed. Refuse first.
        if (inspectKeyRingSupport(armorBytes) !is PgpKeyRingSupport.Supported) return null

        // A parse failure anywhere propagates: a blob whose tail cannot be parsed must not be
        // accepted on the strength of a valid-looking prefix (the whole armor is what gets written).
        val objects = ByteArrayInputStream(armorBytes).use { stream ->
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(stream), JcaKeyFingerprintCalculator())
            generateSequence { factory.nextObject() }.toList()
        }
        val ring = (objects.singleOrNull() as? PGPPublicKeyRing) ?: return null
        return ring.publicKeys.asSequence().firstOrNull { it.isMasterKey }
            ?.fingerprint?.joinToString("") { byte -> String.format("%02X", byte) }
    }

    override suspend fun deletePgpKey(keyId: Long): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            // Delete EVERY file that carries this key, by scanning the key directory — not the
            // single path recorded on the listed entry. A keypair lives in two files
            // (<name>_public_ring.asc + <name>_secret_ring.asc), and processKeyRing emits a
            // public-typed entry from the SECRET ring too; getKeys' last-file-wins dedup then
            // pointed the listed public entry's path at the secret file, so the old
            // delete-by-recorded-path removed the secret file twice and left the public ring
            // behind — the key stayed in the list until a second delete.
            val user = userPreferences.getUser() as AppUser.LoggedIn
            var deletedAny = false
            // Each file is parsed to decide whether it holds only this key, and then deleted on the
            // strength of that answer - read and delete both inside, or a sync could replace a ring
            // between the two and the delete would remove a file nobody inspected.
            inKeyDirectory(user.userName) {
                keyFiles(user.userName).forEach { file ->
                    val primaries = runCatching { processKeyRing(file.absolutePath, file.name) }
                        .getOrElse { emptyList() }
                        .map { it.key }
                    if (primaries.none { it.keyId == keyId }) return@forEach
                    if (primaries.any { it.keyId != keyId }) {
                        // Mixed-ring file (e.g. an imported collection): deleting the whole file would
                        // take unrelated keys with it. Leave it and surface the partial delete.
                        KLogger.e { "deletePgpKey: ${file.name} also contains other keys; not deleting it" }
                        return@forEach
                    }
                    if (file.delete()) deletedAny = true
                }
            }
            if (deletedAny) {
                Outcome.Success(Unit)
            } else {
                Outcome.Error("key not found", PgpFailure.DeleteKeyPairFailure)
            }
        }.onFailure {
            KLogger.e(it) { "failed to delete key pair" }
        }.getOrElse {
            Outcome.Error("failed to delete key pair", PgpFailure.DeleteKeyPairFailure)
        }
    }

    override suspend fun transferPgpKeys(device: TrustedDevice): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        runCatching {
            val user = userPreferences.getUser() as AppUser.LoggedIn
            val keysDir = File("$pgpDir${user.userName}")
            if (!keysDir.isDirectory || keysDir.listFiles()?.isEmpty() != false) {
                return@withContext Outcome.Error("no pgp keys to transfer", PgpFailure.GeneralPgpError("empty"))
            }
            val bundleBytes = DirectoryBundler.bundle(keysDir)
            val fileName = "${user.userName.hashCode()}_pgp"
            pgpTransferService.transferPgpBundle(bundleBytes, fileName, device)
        }.getOrElse {
            KLogger.e(it) { "failed to transfer pgp keys" }
            Outcome.Error("failed to transfer pgp keys: ${it.message}", TransferFailure.GeneralTransferFailure)
        }
    }

    override suspend fun pushPgpKeys(device: TrustedDevice): Outcome<Unit> = transferPgpKeys(device)

    override suspend fun pullPgpKeys(device: TrustedDevice): Outcome<Unit> = withContext(coroutinesContextFacade.io) {
        when (val pullOutcome = pgpTransferService.pullPgpBundle(device = device)) {
            is Outcome.Error -> pullOutcome
            is Outcome.Success -> {
                // The transfer service already decrypted the (post-quantum) response.
                val bundle = pullOutcome.value
                if (bundle.isEmpty()) {
                    return@withContext Outcome.Success(Unit)
                }
                val unbundleResult = runCatching {
                    val user = userPreferences.getUser() as AppUser.LoggedIn
                    val destDir = File("$pgpDir${user.userName}")
                    DirectoryBundler.unbundle(bundle, destDir)
                }.onFailure {
                    if (it is CancellationException) throw it
                    KLogger.e(it) { "pgp sync pull unbundle failed" }
                }
                if (unbundleResult.isFailure) {
                    Outcome.Error("failed to apply pgp sync pull", PgpFailure.GeneralPgpError("sync pull unbundle failed"))
                } else {
                    Outcome.Success(Unit)
                }
            }
        }
    }

    /**
     * A parsed key entry plus its provenance: [fromPublicRing] is true only when the file held an
     * actual [PGPPublicKeyRing] — false for the public-typed entry synthesized from a secret ring,
     * whose path points at the secret file and must never win the listing over a real public ring.
     */
    private data class RingEntry(val key: PgpKey, val fromPublicRing: Boolean)

    /**
     * Whether every key in the file at [filePath] uses an algorithm this build can read.
     *
     * Read at the point of use rather than cached on [PgpKey]: files arrive by sync as raw bytes
     * without passing through import, so the listing is not a reliable place to have decided this.
     * An unreadable file answers [PgpKeyRingSupport.NotAKeyRing], which callers treat as "no
     * objection" — they have their own handling for a file that will not parse.
     */
    private fun supportOf(filePath: String): PgpKeyRingSupport =
        runCatching { FileInputStream(filePath).use { inspectKeyRingSupport(it) } }
            .getOrElse { PgpKeyRingSupport.NotAKeyRing }

    private fun processKeyRing(filePath: String, fileName: String): List<RingEntry> {
        val result = mutableListOf<RingEntry>()
        FileInputStream(filePath).use { fileStream ->
            val keyInputStream = PGPUtil.getDecoderStream(fileStream)
            val pgpFactory = PGPObjectFactory(keyInputStream, JcaKeyFingerprintCalculator())
            while (true) {
                val obj = pgpFactory.nextObject() ?: break

                when (obj) {
                    is PGPPublicKeyRing -> {
                        val keys = obj.publicKeys.asSequence().toList()
                        val primary = keys.firstOrNull { it.isMasterKey }
                        val subKeys = keys.filter { !it.isMasterKey }

                        primary?.let { primaryKey ->
                            val mappedSubKeys = subKeys.map { subKey -> subKey.toPgpKey(filePath, fileName, listOf()) }
                            primaryKey.toPgpKey(filePath, fileName, mappedSubKeys)
                        }?.let {
                            result.add(RingEntry(it, fromPublicRing = true))
                        }
                    }
                    is PGPSecretKeyRing -> {
                        val keys = obj.secretKeys.asSequence().toList()
                        val primary = keys.firstOrNull { it.isMasterKey }
                        val subKeys = keys.filter { !it.isMasterKey }

                        primary?.let { primaryKey ->
                            val mappedSubKeys = subKeys.map { subKey -> subKey.toPgpKey(filePath, fileName, listOf()) }
                            primaryKey.toPgpKey(filePath,fileName, mappedSubKeys).let {
                                result.add(RingEntry(it, fromPublicRing = false))
                            }
                            primaryKey.publicKey.toPgpKey(filePath, fileName, mappedSubKeys).let {
                                result.add(RingEntry(it, fromPublicRing = false))
                            }
                        }
                    }
                    else -> continue
                }
        }
        }

        return result
    }
}
