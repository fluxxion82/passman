package ai.passman.repo.crypto

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.HybridKem
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
 * Owns this device's post-quantum hybrid (X25519 + ML-KEM-768) keypair — the recipient key for
 * suite-v3 payloads. Generated once per user and persisted with its **private** half sealed under
 * `KeyringSubkeys.hybridKeyFileKey(dmk)` ([KeyFileEnvelope]), so it unlocks exactly when the device
 * keyring does. The public half is derived on load; only the private half is stored.
 *
 * ## Why the keyring subkey and not the vault root
 *
 * This key is the device's *pairing identity*. If it were wrapped under a root that lives inside the
 * vault envelope, restoring or losing the vault database would change that root and make this file
 * undecryptable — which permanently breaks every upgraded pairing and is recoverable only by
 * re-pairing every peer by hand. The device master key lives in its own small file, does not rotate
 * on a password change, and has nothing to do with the vault, so deleting the vault database costs
 * the user their passwords and not their device identity.
 *
 * ## Migration off the RSA identity
 *
 * Files written before the keyring existed are `CryptoEnvelope` v2, sealed under the RSA identity in
 * the PKCS#12 store. The first successful load of one decrypts it through [CryptoService] and rewrites
 * it under the subkey; after that the legacy key is never resolved again, which is why it is a lazy
 * lookup rather than a constructor dependency. `PUBLIC_ENCRYPTION_KEY_HANDLE` is gone entirely — this
 * class no longer writes RSA — and [PRIVATE_DECRYPTION_KEY_HANDLE] stays only until that read path
 * can be dropped.
 *
 * ## What is never allowed to happen
 *
 * Silently generating a replacement for a key that is still good. Every peer already holding the old
 * public key is orphaned by that, with no error anywhere. So generation happens on exactly two paths:
 * there is no file at all — the one silent case — or there is one that could not be used, which has
 * been quarantined outside `keystore/<user>/` and reported at error level with the path in the
 * message. "Could not be used" covers a failed GCM tag *and* a zero-length file, which is an existing
 * file like any other and not the absence of one. Anything that means "we could not tell" — no session
 * key, no legacy RSA key, a failed quarantine — leaves the file untouched and fails the call instead.
 */
class HybridKeyManager(
    private val platform: Platform,
    private val cryptoService: CryptoService,
    private val userPreferences: UserPreferences,
    private val trustedDevices: TrustedDevicesRepository,
) {
    private var cachedUser: String? = null
    private var cached: HybridKem.KeyPair? = null
    private val loadMutex = Mutex()

    /** The current user's hybrid keypair, creating + persisting it on first use. Null if signed out. */
    suspend fun getKeyPair(): HybridKem.KeyPair? {
        val user = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName ?: return null
        // Serialise first use: two concurrent callers must not both generate a keypair — the loser's
        // file write would orphan whichever public key the winner already handed to a peer.
        loadMutex.withLock {
            cached?.let { if (cachedUser == user) return it }

            val keyPair = runCatching { loadOrCreate(user) }.getOrElse {
                KLogger.e(it) { "hybrid key load/create failed" }
                return null
            }
            cachedUser = user
            cached = keyPair
            return keyPair
        }
    }

    /** Wire form of the current user's hybrid public key (`x25519 | mlkemLen | mlkem`). */
    suspend fun getPublicKeySerialized(): ByteArray? =
        getKeyPair()?.let { EnvelopeCodec.serializePublicKey(it.publicKey) }

    private suspend fun loadOrCreate(user: String): HybridKem.KeyPair {
        // The session key first, before anything on disk is read or moved. Nothing here can open an
        // existing key file or seal a new one without it, and discovering that *after* quarantining
        // would have thrown away a perfectly good key.
        val sessionKey = sessionKey()

        val file = keyFile(user)
        // `exists()`, not `exists() && length() > 0`: a zero-byte file is an *existing* file. Treating
        // it as absent skipped the quarantine and published a new identity in silence — see the empty
        // branch below for why it cannot be handled by any of the others.
        if (file.exists()) {
            val stored = file.readBytes()
            val existing = when {
                // Zero length is not a format. It is not a PMKF envelope and it cannot be an RSA
                // envelope either, so there is no intact key here for the legacy branch to protect and
                // no reason to consult the RSA identity. Unusable, unambiguously — quarantine it.
                stored.isEmpty() -> Result.failure(
                    IllegalStateException("$FILE_NAME exists but is zero length; it holds no key material"),
                )

                KeyFileEnvelope.isKeyFileEnvelope(stored) ->
                    runCatching { decodeKeyPair(KeyFileEnvelope.open(stored, KEY_FILE_PURPOSE, sessionKey)) }

                // Legacy: RSA-wrapped by a build that predates the keyring. Refusing outright when the
                // legacy key is unavailable is the point — the file may be perfectly intact, and this
                // is the one branch where "generate a new one" would destroy a working identity
                // without any evidence that it was broken.
                else -> {
                    val legacy = legacyPrivateKey() ?: error(
                        "$FILE_NAME is RSA-wrapped and the legacy identity key is unavailable; refusing to replace it",
                    )
                    runCatching { decodeKeyPair(cryptoService.decryptBytes(stored, legacy)) }
                        .onSuccess { keyPair ->
                            // Rewrite under the subkey. A failure here is not a reason to throw away a
                            // working key: hand it back and let the next login retry the migration.
                            runCatching { persist(file, keyPair, sessionKey) }.onFailure {
                                KLogger.e(it) { "hybrid key migration write failed for $user; retrying next login" }
                            }
                        }
                }
            }
            existing.getOrNull()?.let { return it }
            quarantine(file, user, existing.exceptionOrNull())
        }
        val keyPair = HybridKem.generateKeyPair()
        persistNew(file, keyPair, sessionKey)
        KLogger.d { "generated hybrid keypair for $user" }
        return keyPair
    }

    /**
     * Move an unusable key file out of `keystore/<user>/` and say so where the user can act on it.
     *
     * Every path that reaches here is about to replace this device's pairing identity, so both halves
     * are load bearing. The move preserves the old bytes — which may be a *good* key: a restored or
     * mismatched `keyring.pmk` fails the GCM tag in exactly the same way real corruption does, and a
     * tag cannot say which — and it is what licenses the regeneration that follows. If it throws,
     * nothing is generated: a file we could not get out of the way is not a file we may write over.
     *
     * The destination is one level up, outside the directory keystore sync bundles, so the artifact is
     * never put on the wire.
     *
     * The message goes out at error level *with the path in it* because that path is the recovery
     * route, and because nothing else tells the user. The affected `TrustedDevice`s are marked for
     * re-verification before anything is generated, so the staleness is recorded even if the caller
     * dies between the quarantine and the new key landing on disk.
     */
    private suspend fun quarantine(file: File, user: String, cause: Throwable?) {
        trustedDevices.markSignedHybridPairingsForReverification()
        // Logged before the move, so a move that fails still records *why* the file was unreadable.
        cause?.let { KLogger.e(it) { "hybrid key load failed; quarantining unreadable file for $user" } }
        // A *claimed* destination, not a bare timestamp name: two quarantines within one millisecond
        // used to collide, and the REPLACE_EXISTING move then destroyed the first preserved copy.
        val quarantine = KeyFilePublishing.claimQuarantineDestination(file.parentFile.parentFile, FILE_NAME)
        DurableFiles.replace(file, quarantine)
        KLogger.e {
            "$FILE_NAME for $user was unusable and has been moved to ${quarantine.absolutePath}. " +
                "A new hybrid identity will be generated, so every device paired with this one still " +
                "holds the old public key and has to be paired again. If the cause was a restored or " +
                "mismatched ${DirectoryBundler.KEYRING_FILE_NAME} rather than a damaged key file, the " +
                "original key is intact in that quarantined file and restoring it together with the " +
                "matching ${DirectoryBundler.KEYRING_FILE_NAME} recovers the identity."
        }
    }

    /**
     * Publish a **fresh** keypair, claiming the name with `O_EXCL` — reached only when no usable
     * file exists (none at all, or the unusable one was just quarantined away). The `file.exists()`
     * gate and this write are separated by a keygen, and another process — no single-instance lock
     * on desktop — can run its own bootstrap in that window. Whoever loses a rename-based publish
     * would orphan the winner's public key for every peer already holding it, silently; losing the
     * `CREATE_NEW` claim instead fails this load loudly, and the next load adopts the winner's file.
     */
    private fun persistNew(file: File, keyPair: HybridKem.KeyPair, sessionKey: VaultSessionKey) {
        val sealed = sealPrivate(keyPair, sessionKey)
        file.parentFile?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }
        check(KeyFilePublishing.publishNew(file, sealed)) {
            "$FILE_NAME appeared while a replacement keypair was being generated; another process won " +
                "the claim - discarding this keypair and loading the published one next time"
        }
    }

    /** Rewrite an existing file in place (the RSA→subkey migration). Temp + atomic replace. */
    private fun persist(file: File, keyPair: HybridKem.KeyPair, sessionKey: VaultSessionKey) {
        val sealed = sealPrivate(keyPair, sessionKey)
        file.parentFile?.apply { mkdirs(); let(SecureFiles::ownerOnlyDir) }
        // Write via temp + rename so a crash mid-write can't leave a corrupt half-written key file
        // (which would permanently fail decryption of anything sealed to this key). The temp lives in
        // the directory being published into, because the rename has to stay on one filesystem — and
        // that is a directory keystore sync bundles, which is why `DirectoryBundler` filters
        // TEMP_FILE_SUFFIX by pattern in both directions. Renaming the suffix here without changing
        // that filter puts private key bytes on the wire.
        val tmp = File.createTempFile("${file.name}.", DirectoryBundler.TEMP_FILE_SUFFIX, file.parentFile)
        SecureFiles.ownerOnly(tmp) // owner-only before any key-bearing byte is written
        try {
            tmp.outputStream().use { out ->
                out.write(sealed)
                out.flush()
                out.fd.sync() // the rename is only meaningful once the content is on stable storage
            }
            // Not `renameTo` + delete-then-retry: that branch is the *normal* path on Windows, which
            // the desktop app ships, and it leaves the key under neither name until the retry lands.
            DurableFiles.replace(tmp, file)
        } finally {
            tmp.delete()
        }
        SecureFiles.ownerOnly(file)
    }

    private fun sealPrivate(keyPair: HybridKem.KeyPair, sessionKey: VaultSessionKey): ByteArray {
        val blob = encodePrivate(keyPair.privateKey)
        return try {
            KeyFileEnvelope.seal(blob, KEY_FILE_PURPOSE, sessionKey)
        } finally {
            blob.fill(0)
        }
    }

    private fun keyFile(user: String): File =
        File("${platform.getLocalPath()}/keystore/$user/$FILE_NAME")

    /**
     * The unwrapped device master key for this session. Fails loudly when nothing is bound: without
     * it this class cannot tell an intact key file from a broken one, and guessing is how identities
     * get replaced.
     */
    private suspend fun sessionKey(): VaultSessionKey =
        sessionScope().get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()

    /**
     * The RSA private key, for reading a pre-keyring key file exactly once. Resolved through
     * `runCatching` because the definition takes two parameters and throws rather than returning null
     * on a scope whose login never warmed it; either way the answer is "no legacy key", and this class
     * treats that as a reason to leave the file alone.
     */
    private suspend fun legacyPrivateKey(): CryptoKey? =
        runCatching { sessionScope().get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) }.getOrNull()

    private suspend fun sessionScope() = KoinPlatform.getKoin().getOrCreateScope(
        "session-${userPreferences.getSessionId()}",
        named("sessionScope"),
    )

    // Private-key blob: x25519(32) | mlkemLen(2,BE) | mlkem. Public halves are re-derived on load.
    // Unchanged from the RSA-wrapped generation: only the envelope around it moved.
    private fun encodePrivate(priv: HybridKem.HybridPrivateKey): ByteArray {
        val out = ByteArray(32 + 2 + priv.mlkem.size)
        priv.x25519.copyInto(out, 0)
        out[32] = ((priv.mlkem.size ushr 8) and 0xFF).toByte()
        out[33] = (priv.mlkem.size and 0xFF).toByte()
        priv.mlkem.copyInto(out, 34)
        return out
    }

    private fun decodeKeyPair(blob: ByteArray): HybridKem.KeyPair {
        require(blob.size > 34) { "hybrid key blob too short" }
        val mlkemLen = ((blob[32].toInt() and 0xFF) shl 8) or (blob[33].toInt() and 0xFF)
        require(blob.size == 34 + mlkemLen) { "hybrid key blob length mismatch" }
        val priv = HybridKem.HybridPrivateKey(
            x25519 = blob.copyOfRange(0, 32),
            mlkem = blob.copyOfRange(34, blob.size),
        )
        return HybridKem.KeyPair(HybridKem.publicKeyOf(priv), priv)
    }

    private companion object {
        val FILE_NAME = DirectoryBundler.HYBRID_KEY_FILE_NAME
        val KEY_FILE_PURPOSE = KeyFilePurpose.HYBRID
    }
}
