package ai.passman.repo.crypto

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.MlDsa
import ai.passman.crypto.io.DurableFiles
import ai.passman.crypto.keyring.KeyFileEnvelope
import ai.passman.crypto.keyring.KeyFilePurpose
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.repo.io.SecureFiles
import ai.passman.logging.KLogger
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import java.io.File
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.koin.core.qualifier.named
import org.koin.mp.KoinPlatform

/**
 * Owns this device's ML-DSA-65 sender-signing keypair. The private key is stored as its 32-byte seed,
 * sealed under `KeyringSubkeys.mlDsaKeyFileKey(dmk)` ([KeyFileEnvelope]). Its public key is
 * deterministically reconstructed on load, keeping the device-local signing key out of synced
 * keystore bundles.
 *
 * Everything `HybridKeyManager`'s KDoc says about *why* the keyring subkey — and about never
 * generating a replacement for a key that may still be good — applies here identically, and matters
 * slightly more: after the pairing upgrade a peer rejects any envelope signed by an ML-DSA key other
 * than the one it recorded, so a silently regenerated seed does not degrade sync, it stops it.
 */
class MlDsaKeyManager(
    private val platform: Platform,
    private val cryptoService: CryptoService,
    private val userPreferences: UserPreferences,
    private val trustedDevices: TrustedDevicesRepository,
) {
    private var cachedUser: String? = null
    private var cached: MlDsa.KeyPair? = null
    private val loadMutex = Mutex()

    /** The current user's ML-DSA signing keypair, creating + persisting it on first use. */
    suspend fun getKeyPair(): MlDsa.KeyPair? {
        val user = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName ?: return null
        loadMutex.withLock {
            cached?.let { if (cachedUser == user) return it }

            val keyPair = runCatching { loadOrCreate(user) }.getOrElse {
                KLogger.e(it) { "ML-DSA key load/create failed" }
                return null
            }
            cachedUser = user
            cached = keyPair
            return keyPair
        }
    }

    /** Wire form of the current user's ML-DSA-65 public key. */
    suspend fun getPublicKeySerialized(): ByteArray? = getKeyPair()?.publicKey?.copyOf()

    private suspend fun loadOrCreate(user: String): MlDsa.KeyPair {
        // Before anything on disk is read or moved — see HybridKeyManager.loadOrCreate.
        val sessionKey = sessionKey()

        val file = keyFile(user)
        // `exists()` alone — see HybridKeyManager.loadOrCreate: a zero-byte file is an existing file,
        // and classifying it as absent regenerated the signing identity with no quarantine and no
        // message.
        if (file.exists()) {
            val stored = file.readBytes()
            val existing = when {
                stored.isEmpty() -> Result.failure(
                    IllegalStateException("$FILE_NAME exists but is zero length; it holds no key material"),
                )

                KeyFileEnvelope.isKeyFileEnvelope(stored) ->
                    runCatching { decode(KeyFileEnvelope.open(stored, KEY_FILE_PURPOSE, sessionKey)) }

                else -> {
                    val legacy = legacyPrivateKey() ?: error(
                        "$FILE_NAME is RSA-wrapped and the legacy identity key is unavailable; refusing to replace it",
                    )
                    runCatching { decode(cryptoService.decryptBytes(stored, legacy)) }
                        .onSuccess { keyPair ->
                            runCatching { persist(file, keyPair, sessionKey) }.onFailure {
                                KLogger.e(it) { "ML-DSA key migration write failed for $user; retrying next login" }
                            }
                        }
                }
            }
            existing.getOrNull()?.let { return it }
            quarantine(file, user, existing.exceptionOrNull())
        }
        val keyPair = MlDsa.generateKeyPair()
        persistNew(file, keyPair, sessionKey)
        KLogger.d { "generated ML-DSA keypair for $user" }
        return keyPair
    }

    /**
     * Preserve an unusable key file outside `keystore/<user>/` and surface the path — see
     * `HybridKeyManager.quarantine` for why both halves matter. The stakes differ only in degree: a
     * replaced hybrid key degrades a peer to a legacy path, a replaced signing seed makes an upgraded
     * peer reject this device outright.
     */
    private suspend fun quarantine(file: File, user: String, cause: Throwable?) {
        trustedDevices.markSignedHybridPairingsForReverification()
        cause?.let { KLogger.e(it) { "ML-DSA key load failed; quarantining unreadable file for $user" } }
        // A *claimed* destination — see HybridKeyManager.quarantine: a bare timestamp name can
        // collide within one millisecond, and the REPLACE_EXISTING move destroys the earlier copy.
        val quarantine = KeyFilePublishing.claimQuarantineDestination(file.parentFile.parentFile, FILE_NAME)
        DurableFiles.replace(file, quarantine)
        KLogger.e {
            "$FILE_NAME for $user was unusable and has been moved to ${quarantine.absolutePath}. " +
                "A new ML-DSA signing identity will be generated, and an upgraded peer rejects any " +
                "envelope signed by a key other than the one it recorded, so every paired device has " +
                "to be paired again. If the cause was a restored or mismatched " +
                "${DirectoryBundler.KEYRING_FILE_NAME} rather than a damaged key file, the original " +
                "seed is intact in that quarantined file and restoring it together with the matching " +
                "${DirectoryBundler.KEYRING_FILE_NAME} recovers the identity."
        }
    }

    /**
     * Publish a **fresh** keypair, claiming the name with `O_EXCL` — see
     * `HybridKeyManager.persistNew`. Losing the claim fails this load loudly rather than orphaning
     * the winner's published key; the next load adopts the winner's file.
     */
    private fun persistNew(file: File, keyPair: MlDsa.KeyPair, sessionKey: VaultSessionKey) {
        val sealed = sealSeed(keyPair, sessionKey)
        file.parentFile?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }
        check(KeyFilePublishing.publishNew(file, sealed)) {
            "$FILE_NAME appeared while a replacement keypair was being generated; another process won " +
                "the claim - discarding this keypair and loading the published one next time"
        }
    }

    /** Rewrite an existing file in place (the RSA→subkey migration). Temp + atomic replace. */
    private fun persist(file: File, keyPair: MlDsa.KeyPair, sessionKey: VaultSessionKey) {
        val sealed = sealSeed(keyPair, sessionKey)
        file.parentFile?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }
        // Temp + rename, temp inside the published directory: see HybridKeyManager.persist for why
        // the suffix is DirectoryBundler.TEMP_FILE_SUFFIX and why the move goes through DurableFiles.
        val tmp = File.createTempFile("${file.name}.", DirectoryBundler.TEMP_FILE_SUFFIX, file.parentFile)
        SecureFiles.ownerOnly(tmp)
        try {
            tmp.outputStream().use { out ->
                out.write(sealed)
                out.flush()
                out.fd.sync()
            }
            DurableFiles.replace(tmp, file)
        } finally {
            tmp.delete()
        }
        SecureFiles.ownerOnly(file)
    }

    private fun sealSeed(keyPair: MlDsa.KeyPair, sessionKey: VaultSessionKey): ByteArray {
        val seedCopy = keyPair.privateSeed.copyOf()
        return try {
            KeyFileEnvelope.seal(seedCopy, KEY_FILE_PURPOSE, sessionKey)
        } finally {
            seedCopy.fill(0)
        }
    }

    private fun keyFile(user: String): File =
        File("${platform.getLocalPath()}/keystore/$user/$FILE_NAME")

    private suspend fun sessionKey(): VaultSessionKey =
        sessionScope().get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()

    private suspend fun legacyPrivateKey(): CryptoKey? =
        runCatching { sessionScope().get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) }.getOrNull()

    private suspend fun sessionScope() = KoinPlatform.getKoin().getOrCreateScope(
        "session-${userPreferences.getSessionId()}",
        named("sessionScope"),
    )

    /** Unchanged byte layout: the file holds the bare 32-byte seed, only the envelope around it moved. */
    private fun decode(blob: ByteArray): MlDsa.KeyPair {
        try {
            require(blob.size == MlDsa.PRIVATE_SEED_BYTES) { "bad ML-DSA private seed length" }
            val privateSeed = blob.copyOf()
            return MlDsa.KeyPair(MlDsa.publicKeyOf(privateSeed), privateSeed)
        } finally {
            blob.fill(0)
        }
    }

    private companion object {
        val FILE_NAME = DirectoryBundler.ML_DSA_KEY_FILE_NAME
        val KEY_FILE_PURPOSE = KeyFilePurpose.ML_DSA
    }
}
